/** Custom shapes for section_divider_band_v1 layout */

function isSectionDividerBandLayout(layoutId) {
  return /^section_divider_band/i.test(String(layoutId || ''))
}

function sectionDividerBandGeom(canvasW = 1920, canvasH = 1080) {
  const sx = canvasW / 1920
  const sy = canvasH / 1080
  
  const bandH = Math.round(400 * sy)
  const centerY = canvasH / 2
  const yTop = Math.round(centerY - bandH / 2)
  const yBottom = Math.round(centerY + bandH / 2)
  
  const angleOffset = Math.round(120 * sy)

  return {
    canvasW,
    canvasH,
    bandH,
    yTop,
    yBottom,
    angleOffset,
    headingBox: {
      x: Math.round(160 * sx),
      y: Math.round(centerY - 100 * sy),
      w: Math.round(canvasW - 320 * sx),
      h: Math.round(200 * sy),
    }
  }
}

function renderBandSvg(g, accentColor) {
  const path = `M 0 ${g.yTop - g.angleOffset} 
                L ${g.canvasW} ${g.yTop + g.angleOffset} 
                L ${g.canvasW} ${g.yBottom + g.angleOffset} 
                L 0 ${g.yBottom - g.angleOffset} Z`

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.canvasW} ${g.canvasH}" width="${g.canvasW}" height="${g.canvasH}">
    <path d="${path}" fill="${accentColor}" opacity="0.9" />
    <path d="M 0 ${g.yBottom - g.angleOffset} L ${g.canvasW} ${g.yBottom + g.angleOffset} L ${g.canvasW} ${g.yBottom + g.angleOffset + 30} L 0 ${g.yBottom - g.angleOffset + 30} Z" fill="#000000" opacity="0.15" />
    <path d="M 0 ${g.yTop - g.angleOffset} L ${g.canvasW} ${g.yTop + g.angleOffset} L ${g.canvasW} ${g.yTop + g.angleOffset - 12} L 0 ${g.yTop - g.angleOffset - 12} Z" fill="#ffffff" opacity="0.15" />
  </svg>`
}

function layoutSectionDividerBand(docOrElements, schema, themeTokens, canvas = {}) {
  // Handle both array of elements (older style) or doc object
  let elements = Array.isArray(docOrElements) ? docOrElements : docOrElements?.elements;
  if (!Array.isArray(elements)) return docOrElements;

  const canvasW = canvas.width || 1920
  const canvasH = canvas.height || 1080
  const g = sectionDividerBandGeom(canvasW, canvasH)

  const palette = themeTokens?.palette || {}
  const accent = palette.accent || palette.primary || '#3b82f6'
  
  let out = []
  let injectedSvg = false

  elements.forEach((el) => {
    const slotId = String(el.slotId || '').toUpperCase()
    
    if (slotId === 'BAND') {
      out.push({
        ...el,
        type: 'graphic',
        layer: 1,
        placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
        content: {
          svg: renderBandSvg(g, accent),
          colorMode: 'preserve'
        }
      })
      injectedSvg = true
    } else if (slotId === 'HEADING' || el.role === 'heading') {
      out.push({
        ...el,
        layer: 10,
        placement: {
          x: g.headingBox.x,
          y: g.headingBox.y,
          width: g.headingBox.w,
          height: g.headingBox.h,
          rotation: 0,
          opacity: 1
        },
        content: {
          ...(el.content || {}),
          align: 'center',
          verticalAlign: 'middle',
        }
      })
    } else {
      out.push(el)
    }
  })

  if (!injectedSvg) {
    out.unshift({
      id: 'shp-section-band-custom',
      type: 'graphic',
      layer: 1,
      role: 'decoration',
      slotId: 'BAND',
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: renderBandSvg(g, accent),
        colorMode: 'preserve'
      }
    })
  }

  if (Array.isArray(docOrElements)) {
    return out;
  }
  return { ...docOrElements, elements: out };
}

module.exports = {
  isSectionDividerBandLayout,
  layoutSectionDividerBand,
  sectionDividerBandGeom,
};
