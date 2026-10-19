'use strict'
/** Custom canvas layout for section_divider_numbered_circle_v1 (backend, CJS) */

function isSectionDividerNumberedCircleLayout(layoutId) {
  return layoutId === 'section_divider_numbered_circle_v1'
}

function sectionDividerNumberedCircleGeom(canvasW, canvasH) {
  canvasW = canvasW || 1920
  canvasH = canvasH || 1080
  var cx = canvasW / 2
  var cy = canvasH / 2

  var circleD   = 200
  var circleR   = circleD / 2
  var gap1      = 24
  var headingH  = 120
  var gap2      = 16
  var subtitleH = 72
  var gap3      = 20
  var pillH     = 6
  var pillW     = 64

  var totalH = circleD + gap1 + headingH + gap2 + subtitleH + gap3 + pillH
  var startY = Math.round(cy - totalH / 2)

  var circleY  = startY
  var circleCx = cx
  var circleCy = Math.round(circleY + circleR)

  var headingY  = circleY + circleD + gap1
  var subtitleY = headingY + headingH + gap2
  var pillY     = subtitleY + subtitleH + gap3

  var ringR    = circleR + 16
  var dashLen  = 6
  var dashGap  = 5

  return {
    cx: cx, cy: cy, canvasW: canvasW, canvasH: canvasH,
    circle:    { cx: circleCx, cy: circleCy, r: circleR },
    ring:      { cx: circleCx, cy: circleCy, r: ringR, dashLen: dashLen, dashGap: dashGap },
    numberBox: { x: Math.round(cx - 180), y: Math.round(circleCy - circleR), w: 360, h: circleD },
    headingBox:  { x: Math.round(cx - 640), y: headingY,  w: 1280, h: headingH },
    subtitleBox: { x: Math.round(cx - 520), y: subtitleY, w: 1040, h: subtitleH },
    pill:        { cx: cx, y: pillY, w: pillW, h: pillH },
    auraCy:      circleCy,
  }
}

function renderNumberedCircleDecorSvg(g, accent, accentSoft) {
  var W = g.canvasW, H = g.canvasH
  var ccx = g.circle.cx, ccy = g.circle.cy, r = g.circle.r
  var rr = g.ring.r, dashLen = g.ring.dashLen, dashGap = g.ring.dashGap
  var dashArray = dashLen + ' ' + dashGap

  var dotR = 4
  var cardinals = [
    { x: ccx,      y: ccy - rr },
    { x: ccx + rr, y: ccy      },
    { x: ccx,      y: ccy + rr },
    { x: ccx - rr, y: ccy      },
  ]
  var cardinalDots = cardinals.map(function (p) {
    return '<circle cx="' + Math.round(p.x) + '" cy="' + Math.round(p.y) + '" r="' + dotR + '" fill="' + accent + '" opacity="0.7"/>'
  }).join('\n  ')

  var ruleW = 80, ruleH = 2, ruleGap = 24
  var ruleY = Math.round(ccy - ruleH / 2)
  var leftRuleX  = Math.round(ccx - r - ruleGap - ruleW)
  var rightRuleX = Math.round(ccx + r + ruleGap)

  var pillX = Math.round(ccx - g.pill.w / 2)
  var auraRx = 280, auraRy = 280

  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + W + ' ' + H + '" width="' + W + '" height="' + H + '">' +
    '<defs>' +
      '<radialGradient id="sndcAura" cx="50%" cy="50%" r="50%">' +
        '<stop offset="0%"   stop-color="' + accentSoft + '" stop-opacity="0.65"/>' +
        '<stop offset="50%"  stop-color="' + accentSoft + '" stop-opacity="0.2"/>' +
        '<stop offset="100%" stop-color="' + accentSoft + '" stop-opacity="0"/>' +
      '</radialGradient>' +
    '</defs>' +
    '<ellipse cx="' + ccx + '" cy="' + g.auraCy + '" rx="' + auraRx + '" ry="' + auraRy + '" fill="url(#sndcAura)"/>' +
    '<circle cx="' + ccx + '" cy="' + ccy + '" r="' + rr + '" fill="none" stroke="' + accent + '" stroke-width="1.5" stroke-dasharray="' + dashArray + '" opacity="0.4"/>' +
    cardinalDots +
    '<rect x="' + leftRuleX  + '" y="' + ruleY + '" width="' + ruleW + '" height="' + ruleH + '" rx="' + ruleH + '" fill="' + accent + '" opacity="0.4"/>' +
    '<rect x="' + rightRuleX + '" y="' + ruleY + '" width="' + ruleW + '" height="' + ruleH + '" rx="' + ruleH + '" fill="' + accent + '" opacity="0.4"/>' +
    '<circle cx="' + ccx + '" cy="' + ccy + '" r="' + r + '" fill="' + accent + '" opacity="1"/>' +
    '<rect x="' + pillX + '" y="' + g.pill.y + '" width="' + g.pill.w + '" height="' + g.pill.h + '" rx="' + g.pill.h + '" fill="' + accent + '" opacity="0.88"/>' +
    '</svg>'
}

function layoutSectionDividerNumberedCircle(docOrElements, layoutSchema, themeTokens, canvas) {
  canvas = canvas || {}
  var elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements && docOrElements.elements)
  if (!Array.isArray(elements)) return docOrElements

  var canvasW = canvas.width  || 1920
  var canvasH = canvas.height || 1080
  var g = sectionDividerNumberedCircleGeom(canvasW, canvasH)

  var palette    = (themeTokens && themeTokens.palette) || {}
  var accent     = palette.accent     || palette.primary    || '#6366f1'
  var accentSoft = palette.accentSoft || palette.accentLight || '#eef2ff'

  var out = []

  elements.forEach(function (el) {
    var slotId = String(el.slotId || '').toUpperCase()

    if (slotId === 'SECTION_NUMBER') {
      out.push(Object.assign({}, el, {
        layer: 11,
        placement: { x: g.numberBox.x, y: g.numberBox.y, width: g.numberBox.w, height: g.numberBox.h, rotation: 0, opacity: 1 },
        content:   Object.assign({}, el.content || {}, {
          text: (el.content && el.content.text) || '02',
          runs: null,
          fontSize: 54,
          fontWeight: 900,
          bold: true,
          lineHeight: 1,
          wrap: 'nowrap',
          clipToSlot: false,
          padding: 0,
          paddingX: 0,
          align: 'center',
          verticalAlign: 'center',
          color: '#ffffff',
          colorRole: 'textOnImage',
        }),
      }))
    } else if (slotId === 'HEADING' || el.role === 'heading') {
      out.push(Object.assign({}, el, {
        layer: 10,
        placement: { x: g.headingBox.x, y: g.headingBox.y, width: g.headingBox.w, height: g.headingBox.h, rotation: 0, opacity: 1 },
        content:   Object.assign({}, el.content || {}, { align: 'center', verticalAlign: 'middle' }),
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
    id: 'shp-section-divider-numbered-circle-decor',
    type: 'graphic',
    layer: 1,
    role: 'decoration',
    slotId: 'DECOR',
    placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
    content: { svg: renderNumberedCircleDecorSvg(g, accent, accentSoft), colorMode: 'preserve' },
  })

  if (Array.isArray(docOrElements)) return out
  return Object.assign({}, docOrElements, { elements: out })
}

module.exports = {
  isSectionDividerNumberedCircleLayout,
  layoutSectionDividerNumberedCircle,
  sectionDividerNumberedCircleGeom,
}
