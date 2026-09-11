function isComparisonProsConsLayout(layoutId) {
  return /comparison_pros_cons/i.test(layoutId)
}

function renderMainBlockSvg(w, h, color, isLeft) {
  const r = 60
  // Left block is rounded on the right side. Right block is rounded on the left side.
  const path = isLeft
    ? `M0,0 L${w-r},0 A${r},${r} 0 0,1 ${w},${r} L${w},${h-r} A${r},${r} 0 0,1 ${w-r},${h} L0,${h} Z`
    : `M${w},0 L${r},0 A${r},${r} 0 0,0 0,${r} L0,${h-r} A${r},${r} 0 0,0 ${r},${h} L${w},${h} Z`
    
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}">
    <path d="${path}" fill="${color}" />
  </svg>`
}

function renderNodeAndLineSvg(w, h, color, isLeft, idx) {
  const r = 24
  const lineW = w - r*2
  const lineY = h / 2
  
  // Text for the circle
  const textX = isLeft ? w - r : r
  const numStr = `0${idx+1}`
  
  const circleNode = `
    <circle cx="${textX}" cy="${lineY}" r="${r}" fill="${color}" />
    <text x="${textX}" y="${lineY + 6}" font-size="20" font-weight="700" fill="#ffffff" font-family="system-ui, sans-serif" text-anchor="middle">${numStr}</text>
  `
  
  // Dotted/solid connecting line
  const startX = isLeft ? 0 : r*2
  const endX = isLeft ? lineW : w
  const line = `<line x1="${startX}" y1="${lineY}" x2="${endX}" y2="${lineY}" stroke="${color}" stroke-width="2" stroke-dasharray="4 4" opacity="0.6" />`
  
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" style="overflow:visible">
    ${line}
    ${circleNode}
  </svg>`
}

function renderVsLineSvg(w, h) {
  const cx = w/2
  const cy = h/2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" style="overflow:visible">
    <line x1="${cx}" y1="0" x2="${cx}" y2="${h}" stroke="#e2e8f0" stroke-width="2" />
    <rect x="${cx - 24}" y="${cy - 16}" width="48" height="32" rx="16" fill="#ffffff" stroke="#e2e8f0" stroke-width="2" />
    <text x="${cx}" y="${cy + 5}" font-size="14" font-weight="700" fill="#94a3b8" font-family="system-ui, sans-serif" text-anchor="middle">VS</text>
  </svg>`
}

function comparisonProsConsGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  
  const padX = Math.round(80 * sx)
  const padY = Math.round(80 * sy)
  const headingH = Math.round(120 * sy)
  
  const contentStartY = padY + headingH + Math.round(40 * sy)
  const contentH = canvasH - contentStartY - padY
  
  // Left and Right main blocks
  const blockW = Math.round(300 * sx)
  const blockH = Math.round(400 * sy)
  const blockY = contentStartY + (contentH - blockH) / 2
  
  // Center VS line
  const vsW = 60
  const vsH = contentH - Math.round(80 * sy)
  const vsY = contentStartY + Math.round(40 * sy)
  const vsX = (canvasW - vsW) / 2
  
  const geom = {
    canvasW,
    canvasH,
    headingBox: { x: padX, y: padY, width: canvasW - padX * 2, height: headingH },
    leftBlock: { x: 0, y: blockY, width: blockW, height: blockH },
    rightBlock: { x: canvasW - blockW, y: blockY, width: blockW, height: blockH },
    leftBlockTitle: { x: Math.round(40 * sx), y: blockY + blockH/2 - Math.round(30 * sy), width: blockW - Math.round(80 * sx), height: Math.round(60 * sy) },
    rightBlockTitle: { x: canvasW - blockW + Math.round(40 * sx), y: blockY + blockH/2 - Math.round(30 * sy), width: blockW - Math.round(80 * sx), height: Math.round(60 * sy) },
    vsLine: { x: vsX, y: vsY, width: vsW, height: vsH },
    rows: []
  }
  
  // 5 rows
  const rowH = Math.round(100 * sy)
  const rowGap = (contentH - (rowH * 5)) / 4
  
  let currentY = contentStartY
  
  // Node lines width: space between block and text
  const nodeW = Math.round(140 * sx)
  const leftNodeX = blockW
  const rightNodeX = canvasW - blockW - nodeW
  
  // Text boxes
  // Space available for text: vsX - (blockW + nodeW) - margin
  const textMargin = Math.round(30 * sx)
  const textW = vsX - leftNodeX - nodeW - textMargin * 2
  const leftTextX = leftNodeX + nodeW + textMargin
  const rightTextX = vsX + vsW + textMargin
  
  for (let i = 0; i < 5; i++) {
    geom.rows.push({
      leftNode: { x: leftNodeX, y: currentY, width: nodeW, height: rowH },
      rightNode: { x: rightNodeX, y: currentY, width: nodeW, height: rowH },
      leftTitle: { x: leftTextX, y: currentY + Math.round(10 * sy), width: textW, height: Math.round(40 * sy) },
      leftBody: { x: leftTextX, y: currentY + Math.round(50 * sy), width: textW, height: Math.round(40 * sy) },
      rightTitle: { x: rightTextX, y: currentY + Math.round(10 * sy), width: textW, height: Math.round(40 * sy) },
      rightBody: { x: rightTextX, y: currentY + Math.round(50 * sy), width: textW, height: Math.round(40 * sy) }
    })
    currentY += rowH + rowGap
  }

  return geom
}

const COLORS = {
  left: '#c084fc', // Pastel purple (like screenshot)
  right: '#fbbf24' // Pastel yellow/orange (like screenshot)
}

function layoutComparisonProsCons(docOrElements, schema, themeTokens, canvas = {}) {
  let elements = Array.isArray(docOrElements) ? docOrElements : docOrElements?.elements;
  if (!Array.isArray(elements)) return docOrElements;

  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const layoutId = String(schema?.layout_id || '')
  
  if (!isComparisonProsConsLayout(layoutId)) return docOrElements;
  
  const g = comparisonProsConsGeom(canvasW, canvasH)
  
  let out = []

  elements.forEach((el) => {
    const slotId = String(el.slotId || '').toUpperCase()
    
    if (slotId === 'HEADING') {
      out.push({ ...el, layer: 10, placement: { ...g.headingBox, rotation: 0, opacity: 1 } })
      return
    }

    if (slotId === 'PROS_PROJECT_TITLE') {
      out.push({ ...el, layer: 10, placement: { ...g.leftBlockTitle, rotation: 0, opacity: 1 }, content: { ...el.content, color: '#ffffff', colorOverride: true, align: 'center', verticalAlign: 'middle' } })
      return
    }
    if (slotId === 'CONS_PROJECT_TITLE') {
      out.push({ ...el, layer: 10, placement: { ...g.rightBlockTitle, rotation: 0, opacity: 1 }, content: { ...el.content, color: '#ffffff', colorOverride: true, align: 'center', verticalAlign: 'middle' } })
      return
    }

    const rowMatch = slotId.match(/^(PROS|CONS)_(\d+)_(TITLE|BODY)$/)
    if (rowMatch) {
      const side = rowMatch[1] === 'PROS' ? 'left' : 'right'
      const rIdx = parseInt(rowMatch[2], 10) - 1
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
          align: side === 'left' ? 'right' : 'left'
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

  // Add Left/Right Blocks
  out.unshift({
    id: 'shp-pros-block',
    type: 'graphic',
    layer: 2,
    role: 'decoration',
    placement: { ...g.leftBlock, rotation: 0, opacity: 1 },
    content: { svg: renderMainBlockSvg(g.leftBlock.width, g.leftBlock.height, COLORS.left, true), colorMode: 'preserve' }
  })
  out.unshift({
    id: 'shp-cons-block',
    type: 'graphic',
    layer: 2,
    role: 'decoration',
    placement: { ...g.rightBlock, rotation: 0, opacity: 1 },
    content: { svg: renderMainBlockSvg(g.rightBlock.width, g.rightBlock.height, COLORS.right, false), colorMode: 'preserve' }
  })

  // Add VS Line
  out.unshift({
    id: 'shp-vs-line',
    type: 'graphic',
    layer: 2,
    role: 'decoration',
    placement: { ...g.vsLine, rotation: 0, opacity: 1 },
    content: { svg: renderVsLineSvg(g.vsLine.width, g.vsLine.height), colorMode: 'preserve' }
  })

  // Add nodes and lines
  g.rows.forEach((r, i) => {
    out.unshift({
      id: `shp-pros-node-${i}`,
      type: 'graphic',
      layer: 2,
      role: 'decoration',
      placement: { ...r.leftNode, rotation: 0, opacity: 1 },
      content: { svg: renderNodeAndLineSvg(r.leftNode.width, r.leftNode.height, COLORS.left, true, i), colorMode: 'preserve' }
    })
    out.unshift({
      id: `shp-cons-node-${i}`,
      type: 'graphic',
      layer: 2,
      role: 'decoration',
      placement: { ...r.rightNode, rotation: 0, opacity: 1 },
      content: { svg: renderNodeAndLineSvg(r.rightNode.width, r.rightNode.height, COLORS.right, false, i), colorMode: 'preserve' }
    })
  })

  if (Array.isArray(docOrElements)) {
    return out;
  }
  return { ...docOrElements, elements: out };
}

module.exports = {
  isComparisonProsConsLayout,
  comparisonProsConsGeom,
  layoutComparisonProsCons
}
