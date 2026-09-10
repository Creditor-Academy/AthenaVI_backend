/**
 * Process Linear Business Diagram Layout (Backend)
 * Layout ID: process_linear_business_v1
 * Also supports: process_linear_v1, process_linner_horti_v1, process_linear_horizontal_v2
 *
 * Modular Architecture:
 *  - Each Arrow (Chevron) is an individual graphic element: STEP_n_CHEVRON
 *  - Each Card Box is an individual graphic element: STEP_n_CARD
 *  - Each Icon is an individual graphic element: STEP_n_ICON
 *  - Each Title is an individual text element: STEP_n_TITLE
 *  - Each Body is an individual text element: STEP_n_BODY
 */

const PROCESS_LINEAR_BUSINESS_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Heading
  headingX: 36,
  headingY: 28,
  headingW: 800,
  headingH: 38,

  // Central Chevron Belt
  beltY: 254,
  beltH: 52,
  chevronDepth: 22,
  chevronGap: 3,

  // Card dimensions
  cardW: 118,
  cardH: 158,
  cardRadius: 18,
  cardBorderWidth: 2.5,

  // Icon size
  iconSize: 24,

  // Card text padding
  textPaddingX: 8,
  titleOffsetY: 14,
  titleH: 36,
  bodyOffsetY: 52,
  bodyH: 98,
};

const PROCESS_LINEAR_DEFAULT_COLORS = [
  '#2C3E50', // 1: Dark Slate Navy
  '#2563EB', // 2: Royal Blue
  '#0D9488', // 3: Teal / Cyan
  '#16A34A', // 4: Leaf Green
  '#EAB308', // 5: Warm Yellow / Amber
  '#EA580C', // 6: Vibrant Orange
  '#DC2626', // 7: Crimson Red
];

function isProcessLinearBusinessLayout(layoutId) {
  const s = String(layoutId || '').toLowerCase();
  return (
    s === 'process_linear_business_v1' ||
    s === 'process_linear_business' ||
    s === 'process_linear_v1' ||
    s === 'process_linner_horti_v1' ||
    s === 'process_linear_horizontal_v2'
  );
}

const PROCESS_LINEAR_ICON_PATHS = [
  // 1: Crossed Tools (hammer & wrench)
  `
    <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
    <path d="m9 15-5 5"/>
    <path d="m15 9 5-5"/>
  `,
  // 2: Trophy
  `
    <path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6"/>
    <path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18"/>
    <path d="M4 22h16"/>
    <path d="M10 14.66V17c0 .55-.45 1-1 1H8v4h8v-4h-1c-.55 0-1-.45-1-1v-2.34"/>
    <path d="M6 4h12v5a6 6 0 0 1-12 0V4z" fill="currentColor" fill-opacity="0.35"/>
  `,
  // 3: Price Tag
  `
    <path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z" fill="currentColor" fill-opacity="0.3"/>
    <circle cx="7" cy="7" r="1.5" fill="currentColor"/>
  `,
  // 4: Megaphone / Bullhorn
  `
    <path d="m3 11 18-5v12L3 13v-2z" fill="currentColor" fill-opacity="0.3"/>
    <path d="M11.6 16.8a3 3 0 1 1-5.8-1.6"/>
    <path d="M3 11v2a2 2 0 0 0 2 2h1"/>
  `,
  // 5: Leaf
  `
    <path d="M11 20A7 7 0 0 1 9.8 6.1C15.5 5 17 4.48 19 2c1 2 2 4.18 2 8 0 5.5-4.78 10-10 10Z" fill="currentColor" fill-opacity="0.3"/>
    <path d="M2 21c0-3 1.85-5.36 5.08-6C9.5 14.52 12 13 13 12"/>
  `,
  // 6: Graduation Cap
  `
    <path d="M21.42 10.922a1 1 0 0 0-.019-1.838L12.83 5.18a2 2 0 0 0-1.66 0L2.6 9.08a1 1 0 0 0 0 1.832l8.57 3.908a2 2 0 0 0 1.66 0z" fill="currentColor" fill-opacity="0.3"/>
    <path d="M22 10v6"/>
    <path d="M6 12.5V16a6 3 0 0 0 12 0v-3.5"/>
  `,
  // 7: Book
  `
    <path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H20v20H6.5a2.5 2.5 0 0 1-2.5-2.5Z" fill="currentColor" fill-opacity="0.3"/>
    <path d="M6 2v20"/>
  `,
];

function calculateStepGeometries(stepCount = 7) {
  const g = PROCESS_LINEAR_BUSINESS_GEOM;
  const n = Math.max(2, Math.min(7, stepCount || 7));
  const padLeft = 36;
  const totalUsableW = g.viewW - padLeft * 2;
  const gap = g.chevronGap;
  const totalGaps = (n - 1) * gap;
  const stepW = Math.floor((totalUsableW - totalGaps - g.chevronDepth) / n);

  const steps = [];
  for (let i = 0; i < n; i += 1) {
    const leftX = padLeft + i * (stepW + gap);
    const rightX = leftX + stepW;
    const cx = leftX + stepW / 2 + g.chevronDepth / 2;
    const cy = g.beltY + g.beltH / 2;

    const isOdd = i % 2 === 0;
    const cardX = Math.round(cx - g.cardW / 2);
    const cardY = isOdd ? g.beltY - g.cardH - 2 : g.beltY + g.beltH + 2;

    steps.push({
      index: i,
      stepNum: i + 1,
      isOdd,
      leftX,
      rightX,
      stepW,
      cx,
      cy,
      cardX,
      cardY,
      cardW: g.cardW,
      cardH: g.cardH,
      color: PROCESS_LINEAR_DEFAULT_COLORS[i % PROCESS_LINEAR_DEFAULT_COLORS.length],
      iconPaths: PROCESS_LINEAR_ICON_PATHS[i % PROCESS_LINEAR_ICON_PATHS.length],
    });
  }

  return steps;
}

function buildSingleChevronSvg(stepW, beltH, chevronDepth) {
  const midY = beltH / 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${stepW + chevronDepth} ${beltH}" width="100%" height="100%" fill="none">
    <path d="M 0 0 L ${chevronDepth} ${midY} L 0 ${beltH} L ${stepW} ${beltH} L ${stepW + chevronDepth} ${midY} L ${stepW} 0 Z" fill="currentColor" />
  </svg>`;
}

function buildSingleCardSvg(cardW, cardH, r, isOdd, borderWidth = 2.5) {
  const inset = borderWidth / 2;
  let pathD = '';
  if (isOdd) {
    pathD = `M ${inset} ${r + inset} A ${r} ${r} 0 0 1 ${r + inset} ${inset} L ${cardW - r - inset} ${inset} A ${r} ${r} 0 0 1 ${cardW - inset} ${r + inset} L ${cardW - inset} ${cardH - inset} L ${inset} ${cardH - inset} Z`;
  } else {
    pathD = `M ${inset} ${inset} L ${cardW - inset} ${inset} L ${cardW - inset} ${cardH - r - inset} A ${r} ${r} 0 0 1 ${cardW - r - inset} ${cardH - inset} L ${r + inset} ${cardH - inset} A ${r} ${r} 0 0 1 ${inset} ${cardH - r - inset} Z`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${cardW} ${cardH}" width="100%" height="100%" fill="none">
    <path d="${pathD}" fill="#FFFFFF" stroke="currentColor" stroke-width="${borderWidth}" stroke-linejoin="round" />
  </svg>`;
}

function buildSingleIconSvg(iconPaths) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="100%" height="100%" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    ${iconPaths}
  </svg>`;
}

function layoutProcessLinearBusiness(elements = [], schema = {}, palette = {}, canvas = {}) {
  const g = PROCESS_LINEAR_BUSINESS_GEOM;
  const canvasW = canvas?.width || 1000;
  const canvasH = canvas?.height || 560;
  const scaleX = canvasW / g.viewW;
  const scaleY = canvasH / g.viewH;

  const safeElements = Array.isArray(elements) ? elements : [];
  const slots = Array.isArray(schema?.slots) ? schema.slots : [];
  let detectedCount = 0;
  for (let i = 1; i <= 7; i += 1) {
    if (slots.some((s) => s.id === `STEP_${i}_TITLE` || s.id === `STEP_${i}_BODY`) ||
        safeElements.some((el) => el.slotId === `STEP_${i}_TITLE` || el.slotId === `STEP_${i}_BODY`)) {
      detectedCount = i;
    }
  }
  const stepCount = Math.max(detectedCount, 7);
  const steps = calculateStepGeometries(stepCount);

  const prevBySlot = new Map();
  safeElements.forEach((el) => {
    const sid = String(el.slotId || el.id || '').toUpperCase();
    if (sid) prevBySlot.set(sid, el);
  });

  const newId = (prefix) => `${prefix}-${Math.random().toString(36).slice(2, 9)}`;
  const newElements = [];

  // 1. Heading Text Element
  const prevHeading = prevBySlot.get('HEADING');
  const headingSlot = slots.find((s) => s.id === 'HEADING');
  const headingText = prevHeading?.content?.text || prevHeading?.content?.html || headingSlot?.placeholder_text || 'Linear Business Process Diagram';

  newElements.push({
    id: prevHeading?.id || newId('txt-heading'),
    slotId: 'HEADING',
    type: 'text',
    layer: 10,
    placement: {
      x: Math.round(g.headingX * scaleX),
      y: Math.round(g.headingY * scaleY),
      width: Math.round(g.headingW * scaleX),
      height: Math.round(g.headingH * scaleY),
      rotation: 0,
      opacity: 1,
    },
    content: {
      text: headingText,
      align: 'left',
      fontSize: 26,
      fontWeight: 800,
      colorRole: 'text',
      color: '#334155',
      lineHeight: 1.15,
      clipToSlot: false,
    },
  });

  // 2. Individual Graphic Elements per Step
  steps.forEach((step) => {
    const n = step.stepNum;

    const prevChevron = prevBySlot.get(`STEP_${n}_CHEVRON`);
    const prevCard = prevBySlot.get(`STEP_${n}_CARD`);
    const prevIcon = prevBySlot.get(`STEP_${n}_ICON`);

    const chevronColor = prevChevron?.content?.fill || step.color;
    const cardColor = prevCard?.content?.fill || step.color;
    const iconColor = prevIcon?.content?.fill || '#FFFFFF';

    // 2A. Standalone Chevron Arrow Graphic
    const chevronSvg = buildSingleChevronSvg(step.stepW, g.beltH, g.chevronDepth);
    newElements.push({
      id: prevChevron?.id || newId(`grp-step-${n}-chevron`),
      slotId: `STEP_${n}_CHEVRON`,
      type: 'graphic',
      layer: 2,
      role: 'decoration',
      placement: {
        x: Math.round(step.leftX * scaleX),
        y: Math.round(g.beltY * scaleY),
        width: Math.round((step.stepW + g.chevronDepth) * scaleX),
        height: Math.round(g.beltH * scaleY),
        rotation: 0,
        opacity: 1,
      },
      content: {
        svg: chevronSvg,
        colorMode: 'recolorable',
        fill: chevronColor,
        color: chevronColor,
        colorRole: 'primary',
        alt: `Step ${n} Arrow`,
      },
    });

    // 2B. Standalone Card Box Graphic
    const cardSvg = buildSingleCardSvg(step.cardW, step.cardH, g.cardRadius, step.isOdd, g.cardBorderWidth);
    newElements.push({
      id: prevCard?.id || newId(`grp-step-${n}-card`),
      slotId: `STEP_${n}_CARD`,
      type: 'graphic',
      layer: 3,
      role: 'decoration',
      placement: {
        x: Math.round(step.cardX * scaleX),
        y: Math.round(step.cardY * scaleY),
        width: Math.round(step.cardW * scaleX),
        height: Math.round(step.cardH * scaleY),
        rotation: 0,
        opacity: 1,
      },
      content: {
        svg: cardSvg,
        colorMode: 'recolorable',
        fill: cardColor,
        color: cardColor,
        colorRole: 'primary',
        alt: `Step ${n} Box`,
      },
    });

    // 2C. Standalone Icon Graphic (only added if user hasn't deleted it)
    const iconDeleted = prevBySlot.has(`STEP_${n}_ICON_DELETED`);
    if (!iconDeleted) {
      const iconX = Math.round(step.cx - g.iconSize / 2);
      const iconY = Math.round(step.cy - g.iconSize / 2);
      const iconSvg = buildSingleIconSvg(step.iconPaths);

      newElements.push({
        id: prevIcon?.id || newId(`grp-step-${n}-icon`),
        slotId: `STEP_${n}_ICON`,
        type: 'graphic',
        layer: 5,
        role: 'decoration',
        placement: {
          x: Math.round(iconX * scaleX),
          y: Math.round(iconY * scaleY),
          width: Math.round(g.iconSize * scaleX),
          height: Math.round(g.iconSize * scaleY),
          rotation: 0,
          opacity: 1,
        },
        content: {
          svg: iconSvg,
          colorMode: 'recolorable',
          fill: iconColor,
          color: iconColor,
          alt: `Step ${n} Icon`,
        },
      });
    }

    // 2D. STEP_n_TITLE Text Element
    const prevTitle = prevBySlot.get(`STEP_${n}_TITLE`);
    const titleSlot = slots.find((s) => s.id === `STEP_${n}_TITLE`);
    const titleText = prevTitle?.content?.text || prevTitle?.content?.html || titleSlot?.placeholder_text || 'Text goes here';
    const titleX = Math.round((step.cardX + g.textPaddingX) * scaleX);
    const titleY = Math.round((step.cardY + g.titleOffsetY) * scaleY);
    const titleW = Math.round((step.cardW - g.textPaddingX * 2) * scaleX);
    const titleH = Math.round(g.titleH * scaleY);

    newElements.push({
      id: prevTitle?.id || newId(`txt-step-${n}-title`),
      slotId: `STEP_${n}_TITLE`,
      type: 'text',
      layer: 10,
      placement: {
        x: titleX,
        y: titleY,
        width: titleW,
        height: titleH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: titleText,
        align: 'center',
        fontSize: 13.5,
        fontWeight: 800,
        colorRole: 'text',
        color: '#1E293B',
        lineHeight: 1.2,
        clipToSlot: false,
      },
    });

    // 2E. STEP_n_BODY Text Element
    const prevBody = prevBySlot.get(`STEP_${n}_BODY`);
    const bodySlot = slots.find((s) => s.id === `STEP_${n}_BODY`);
    const bodyText = prevBody?.content?.text || prevBody?.content?.html || bodySlot?.placeholder_text || 'Lorem Ipsum is simply dummy text of the printing and typesetting industry.';
    const bodyX = Math.round((step.cardX + g.textPaddingX) * scaleX);
    const bodyY = Math.round((step.cardY + g.bodyOffsetY) * scaleY);
    const bodyW = Math.round((step.cardW - g.textPaddingX * 2) * scaleX);
    const bodyH = Math.round(g.bodyH * scaleY);

    newElements.push({
      id: prevBody?.id || newId(`txt-step-${n}-body`),
      slotId: `STEP_${n}_BODY`,
      type: 'text',
      layer: 10,
      placement: {
        x: bodyX,
        y: bodyY,
        width: bodyW,
        height: bodyH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: bodyText,
        align: 'center',
        fontSize: 10.5,
        fontWeight: 400,
        colorRole: 'muted',
        color: '#64748B',
        lineHeight: 1.35,
        clipToSlot: false,
      },
    });
  });

  return newElements;
}

module.exports = {
  PROCESS_LINEAR_BUSINESS_GEOM,
  PROCESS_LINEAR_DEFAULT_COLORS,
  isProcessLinearBusinessLayout,
  calculateStepGeometries,
  buildSingleChevronSvg,
  buildSingleCardSvg,
  buildSingleIconSvg,
  layoutProcessLinearBusiness,
};
