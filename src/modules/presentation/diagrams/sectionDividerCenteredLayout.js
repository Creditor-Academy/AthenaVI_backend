'use strict'
/** Custom canvas layout for section_divider_numbered_v1 and section_divider_centered_v1 (backend, CJS) */

function isSectionDividerCenteredLayout(layoutId) {
  return layoutId === 'section_divider_centered_v1' || layoutId === 'section_divider_numbered_v1'
}

function isSectionDividerNumberedLayout(layoutId) {
  return layoutId === 'section_divider_numbered_v1' || layoutId === 'section_divider_centered_v1'
}

function sectionDividerCenteredGeom(canvasW, canvasH) {
  canvasW = canvasW || 1920
  canvasH = canvasH || 1080
  const cx = canvasW / 2
  const cy = canvasH / 2

  const numberH   = 80
  const gap1      = 20
  const headingH  = 100
  const gap2      = 16
  const subtitleH = 60
  const gap3      = 24
  const pillH     = 5
  const pillW     = 64

  const totalH = numberH + gap1 + headingH + gap2 + subtitleH + gap3 + pillH
  const startY = Math.round(cy - totalH / 2)

  const numberY   = startY
  const headingY  = numberY + numberH + gap1
  const subtitleY = headingY + headingH + gap2
  const pillY     = subtitleY + subtitleH + gap3

  const sideBarW   = 72
  const sideBarH   = 2
  const sideBarGap = 20
  const sideBarY   = Math.round(numberY + numberH / 2 - sideBarH / 2)
  const auraCy     = Math.round(numberY + numberH / 2)

  return {
    cx: cx, cy: cy, canvasW: canvasW, canvasH: canvasH,
    numberBox:   { x: Math.round(cx - 300), y: numberY,   w: 600,  h: numberH  },
    headingBox:  { x: Math.round(cx - 640), y: headingY,  w: 1280, h: headingH },
    subtitleBox: { x: Math.round(cx - 560), y: subtitleY, w: 1120, h: subtitleH },
    pill:        { cx: cx, y: pillY, w: pillW, h: pillH },
    sideBar:     { w: sideBarW, h: sideBarH, gap: sideBarGap, y: sideBarY },
    auraCy:      auraCy,
  }
}

function renderCenteredDecorSvg(g, accent, accentSoft) {
  const W = g.canvasW
  const H = g.canvasH
  const cx = g.cx
  const auraCy = g.auraCy
  const auraRx = 340
  const auraRy = 180

  var barW  = g.sideBar.w
  var barH  = g.sideBar.h
  var barY  = g.sideBar.y
  var halfTextW = 48
  var leftBarX  = Math.round(cx - halfTextW - g.sideBar.gap - barW)
  var rightBarX = Math.round(cx + halfTextW + g.sideBar.gap)

  var pillW = g.pill.w
  var pillH = g.pill.h
  var pillY = g.pill.y
  var pillX = Math.round(cx - pillW / 2)

  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + W + ' ' + H + '" width="' + W + '" height="' + H + '">' +
    '<defs>' +
      '<radialGradient id="sdcAura" cx="50%" cy="50%" r="50%">' +
        '<stop offset="0%"   stop-color="' + accentSoft + '" stop-opacity="0.8"/>' +
        '<stop offset="50%"  stop-color="' + accentSoft + '" stop-opacity="0.25"/>' +
        '<stop offset="100%" stop-color="' + accentSoft + '" stop-opacity="0"/>' +
      '</radialGradient>' +
    '</defs>' +
    '<ellipse cx="' + cx + '" cy="' + auraCy + '" rx="' + auraRx + '" ry="' + auraRy + '" fill="url(#sdcAura)"/>' +
    '<rect x="' + leftBarX  + '" y="' + barY + '" width="' + barW + '" height="' + barH + '" rx="' + barH + '" fill="' + accent + '" opacity="0.6"/>' +
    '<rect x="' + rightBarX + '" y="' + barY + '" width="' + barW + '" height="' + barH + '" rx="' + barH + '" fill="' + accent + '" opacity="0.6"/>' +
    '<rect x="' + pillX + '" y="' + pillY + '" width="' + pillW + '" height="' + pillH + '" rx="' + pillH + '" fill="' + accent + '" opacity="0.88"/>' +
    '</svg>'
}

function layoutSectionDividerCentered(docOrElements, layoutSchema, themeTokens, canvas) {
  canvas = canvas || {}
  var elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements && docOrElements.elements)
  if (!Array.isArray(elements)) return docOrElements

  var canvasW = canvas.width  || 1920
  var canvasH = canvas.height || 1080
  var g = sectionDividerCenteredGeom(canvasW, canvasH)

  var palette    = (themeTokens && themeTokens.palette) || {}
  var accent     = palette.accent     || palette.primary    || '#6366f1'
  var accentSoft = palette.accentSoft || palette.accentLight || '#eef2ff'

  var out = []

  elements.forEach(function (el) {
    var slotId = String(el.slotId || '').toUpperCase()

    if (slotId === 'SECTION_NUMBER') {
      out.push(Object.assign({}, el, {
        layer: 10,
        placement: { x: g.numberBox.x, y: g.numberBox.y, width: g.numberBox.w, height: g.numberBox.h, rotation: 0, opacity: 1 },
        content:   Object.assign({}, el.content || {}, {
          text: (el.content && el.content.text) || '02',
          runs: null,
          fontSize: 56,
          fontWeight: 900,
          bold: true,
          lineHeight: 1,
          wrap: 'nowrap',
          clipToSlot: false,
          padding: 0,
          paddingX: 0,
          align: 'center',
          verticalAlign: 'center',
          color: accent,
          colorRole: 'accent',
        }),
      }))
    } else if (slotId === 'HEADING' || el.role === 'heading') {
      out.push(Object.assign({}, el, {
        layer: 10,
        placement: { x: g.headingBox.x, y: g.headingBox.y, width: g.headingBox.w, height: g.headingBox.h, rotation: 0, opacity: 1 },
        content:   Object.assign({}, el.content || {}, { align: 'center', verticalAlign: 'center' }),
      }))
    } else if (slotId === 'SUBTITLE' || el.role === 'subheading') {
      out.push(Object.assign({}, el, {
        layer: 10,
        placement: { x: g.subtitleBox.x, y: g.subtitleBox.y, width: g.subtitleBox.w, height: g.subtitleBox.h, rotation: 0, opacity: 1 },
        content:   Object.assign({}, el.content || {}, { align: 'center', verticalAlign: 'top' }),
      }))
    } else {
      out.push(el)
    }
  })

  out.unshift({
    id: 'shp-section-divider-centered-decor',
    type: 'graphic',
    layer: 1,
    role: 'decoration',
    slotId: 'DECOR',
    placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
    content: { svg: renderCenteredDecorSvg(g, accent, accentSoft), colorMode: 'preserve' },
  })

  if (Array.isArray(docOrElements)) return out
  return Object.assign({}, docOrElements, { elements: out })
}

module.exports = {
  isSectionDividerCenteredLayout,
  isSectionDividerNumberedLayout,
  layoutSectionDividerCentered,
  layoutSectionDividerNumbered: layoutSectionDividerCentered,
  sectionDividerCenteredGeom,
}
