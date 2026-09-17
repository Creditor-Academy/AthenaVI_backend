/**
 * Process Linear Horizontal Layout (Backend)
 * Layout ID: process_linear_horizontal_v2
 *
 * Visual Reference: "Linear Process Template"
 *  - 5 Tall Outlined Rounded Rectangle Cards
 *  - Top Zone: Minimal Outline Vector Icons (contract/pen, hand sketching, brain gear, timer, trophy)
 *  - Center Zone: Horizontal Track connecting cards with small dots, and on each card a vibrant
 *                 colored ribbon labeled "STEP 01" .. "STEP 05" in bold white text
 *  - Bottom Zone: Step Title in matching step color + centered description text
 *  - Header: Centered title ("Linear Process Template")
 */

const PROCESS_LINEAR_HORIZONTAL_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Header
  headingX: 100,
  headingY: 28,
  headingW: 800,
  headingH: 38,

  // Cards layout
  cardY: 116,
  cardH: 310,
  cardRadius: 14,
  cardBorderWidth: 1.8,

  // Ribbon Belt
  beltOffsetY: 122,
  beltH: 36,
  beltRadius: 7,

  // Top Icon
  iconOffsetY: 44,
  iconSize: 34,

  // Text below ribbon
  titleOffsetY: 172,
  titleH: 26,
  bodyOffsetY: 202,
  bodyH: 96,
};

const PROCESS_LINEAR_HORIZONTAL_DEFAULT_COLORS = [
  '#F5A623', // 1: Warm Amber / Yellow
  '#FF793F', // 2: Vibrant Orange
  '#E84393', // 3: Magenta / Rose Pink
  '#00CEC9', // 4: Aqua / Turquoise
  '#0984E3', // 5: Royal / Sky Blue
  '#6C5CE7', // 6: Purple
  '#00B894', // 7: Mint Green
];

const PROCESS_LINEAR_HORIZONTAL_DEFAULT_STEPS = [
  {
    title: 'Discovery',
    body: 'Identify core goals, understand stakeholder needs, and align the scope.',
  },
  {
    title: 'Strategy',
    body: 'Formulate strategic roadmaps, allocate resources, and set milestones.',
  },
  {
    title: 'Ideation',
    body: 'Explore creative ideas, build rapid prototypes, and refine concepts.',
  },
  {
    title: 'Execution',
    body: 'Build robust features iteratively, test quality, and ensure excellence.',
  },
  {
    title: 'Launch',
    body: 'Deploy with confidence, track key metrics, and celebrate success.',
  },
];

function isProcessLinearHorizontalLayout(layoutId) {
  const s = String(layoutId || '').toLowerCase().trim();
  return (
    s === 'process_linear_horizontal_v2' ||
    s === 'process_linear_horizontal'
  );
}

function isPlaceholderOrLatin(str) {
  const s = String(str || '').toLowerCase().trim();
  if (!s) return true;
  return (
    s === 'add text here' ||
    s === 'text goes here' ||
    s.includes('lorem ipsum') ||
    s.includes('dolor sit') ||
    s.includes('consectetur') ||
    s.includes('adipiscing') ||
    s.includes('incididunt') ||
    s.includes('at vero eos')
  );
}

const PROCESS_LINEAR_HORIZONTAL_ICON_PATHS = [
  // 1: Contract / Document with pen
  `
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
    <path d="M14 2v6h6"/>
    <line x1="8" y1="13" x2="13" y2="13"/>
    <line x1="8" y1="17" x2="16" y2="17"/>
    <path d="m15 11 3 3"/>
  `,
  // 2: Hand sketching / writing with pen
  `
    <path d="M18 2l4 4-10 10H8v-4L18 2z"/>
    <path d="M14 6l4 4"/>
    <path d="M4 22h6"/>
  `,
  // 3: Head profile with brain gear
  `
    <path d="M16 16c2 0 4-2 4-5.5a5.5 5.5 0 0 0-11 0c0 1.5.5 2.5 1.5 3.5L10 22h6v-2"/>
    <circle cx="14" cy="10" r="2"/>
    <path d="M14 6v2m0 4v2m-4-4h2m4 0h2"/>
  `,
  // 4: Stopwatch / Timer
  `
    <circle cx="12" cy="14" r="7"/>
    <path d="M12 11v3l2 2"/>
    <path d="M10 2h4"/>
    <path d="M12 2v3"/>
  `,
  // 5: Head profile with trophy
  `
    <path d="M14 21v-3a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v3"/>
    <circle cx="10" cy="8" r="4"/>
    <path d="M17 9h4v2a2 2 0 0 1-2 2h-2"/>
    <path d="M19 13v3"/>
    <path d="M17 19h4"/>
  `,
];

function calculateLinearHorizontalStepGeometries(stepCount = 5) {
  const g = PROCESS_LINEAR_HORIZONTAL_GEOM;
  const n = Math.max(2, Math.min(7, stepCount));
  const gap = n <= 3 ? 40 : n <= 4 ? 32 : 24;
  const totalGaps = (n - 1) * gap;
  const padX = n <= 3 ? 120 : n <= 4 ? 70 : 44;
  const usableW = g.viewW - padX * 2;
  const cardW = Math.round((usableW - totalGaps) / n);

  const steps = [];
  for (let i = 0; i < n; i += 1) {
    const cardX = Math.round(padX + i * (cardW + gap));
    const isFirst = i === 0;
    const isLast = i === n - 1;

    steps.push({
      index: i,
      stepNum: i + 1,
      cardX,
      cardY: g.cardY,
      cardW,
      cardH: g.cardH,
      cx: cardX + cardW / 2,
      isFirst,
      isLast,
      gap,
      beltY: g.cardY + g.beltOffsetY,
      beltH: g.beltH,
      iconX: Math.round(cardX + cardW / 2 - g.iconSize / 2),
      iconY: Math.round(g.cardY + g.iconOffsetY - g.iconSize / 2),
      color: PROCESS_LINEAR_HORIZONTAL_DEFAULT_COLORS[i % PROCESS_LINEAR_HORIZONTAL_DEFAULT_COLORS.length],
      iconPaths: PROCESS_LINEAR_HORIZONTAL_ICON_PATHS[i % PROCESS_LINEAR_HORIZONTAL_ICON_PATHS.length],
    });
  }

  return steps;
}

function buildLinearHorizontalCardSvg(step) {
  const g = PROCESS_LINEAR_HORIZONTAL_GEOM;
  const { cardW, cardH, beltH, isFirst, isLast, gap } = step;
  const beltY = g.beltOffsetY;
  const stepLabel = `STEP ${String(step.stepNum).padStart(2, '0')}`;
  const midBeltY = beltY + beltH / 2;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${cardW} ${cardH}" width="100%" height="100%" fill="none">
    <rect x="${g.cardBorderWidth / 2}" y="${g.cardBorderWidth / 2}" width="${cardW - g.cardBorderWidth}" height="${cardH - g.cardBorderWidth}" rx="${g.cardRadius}" fill="#FFFFFF" stroke="#4A5568" stroke-width="${g.cardBorderWidth}" />
    <line x1="0" y1="${midBeltY}" x2="10" y2="${midBeltY}" stroke="#CBD5E1" stroke-width="2" />
    <line x1="${cardW - 10}" y1="${midBeltY}" x2="${cardW}" y2="${midBeltY}" stroke="#CBD5E1" stroke-width="2" />
    <rect x="0" y="${beltY}" width="${cardW}" height="${beltH}" rx="${g.beltRadius}" fill="currentColor" />
    <text x="${cardW / 2}" y="${beltY + beltH / 2 + 5}" text-anchor="middle" fill="#FFFFFF" font-size="12.5" font-weight="800" letter-spacing="1" font-family="system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif">
      ${stepLabel}
    </text>
  </svg>`;
}

function buildLinearHorizontalIconSvg(iconPaths) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="100%" height="100%" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
    ${iconPaths}
  </svg>`;
}

function layoutProcessLinearHorizontal(elements = [], schema = {}, palette = {}, canvas = {}) {
  const g = PROCESS_LINEAR_HORIZONTAL_GEOM;
  const canvasW = canvas?.width || 1000;
  const canvasH = canvas?.height || 560;
  const scaleX = canvasW / g.viewW;
  const scaleY = canvasH / g.viewH;

  const safeElements = Array.isArray(elements) ? elements : [];
  const slots = Array.isArray(schema?.slots) ? schema.slots : [];

  let detectedCount = 0;
  for (let i = 1; i <= 7; i += 1) {
    if (
      slots.some((s) => s.id === `STEP_${i}_TITLE` || s.id === `STEP_${i}_BODY`) ||
      safeElements.some((el) => el.slotId === `STEP_${i}_TITLE` || el.slotId === `STEP_${i}_BODY`)
    ) {
      detectedCount = i;
    }
  }
  const stepCount = detectedCount >= 2 ? detectedCount : 5;
  const steps = calculateLinearHorizontalStepGeometries(stepCount);

  const prevBySlot = new Map();
  safeElements.forEach((el) => {
    const sid = String(el.slotId || el.id || '').toUpperCase();
    if (sid) prevBySlot.set(sid, el);
  });

  const newId = (prefix) => `${prefix}-${Math.random().toString(36).slice(2, 9)}`;
  const newElements = [];

  // 1. HEADING
  const prevHeading = prevBySlot.get('HEADING');
  const headingSlot = slots.find((s) => s.id === 'HEADING');
  const headingText =
    prevHeading?.content?.text ||
    prevHeading?.content?.html ||
    headingSlot?.placeholder_text ||
    'Linear Process Template';

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
      align: 'center',
      fontSize: 26,
      fontWeight: 800,
      colorRole: 'text',
      color: prevHeading?.content?.color || '#222222',
      lineHeight: 1.15,
      clipToSlot: false,
    },
  });

  // 2. Track Line background
  const firstStep = steps[0];
  const lastStep = steps[steps.length - 1];
  const midBeltY = g.cardY + g.beltOffsetY + g.beltH / 2;
  const trackStartX = Math.round((firstStep.cardX - 16) * scaleX);
  const trackEndX = Math.round((lastStep.cardX + lastStep.cardW + 16) * scaleX);

  newElements.push({
    id: prevBySlot.get('PROCESS_TRACK')?.id || newId('shp-track'),
    slotId: 'PROCESS_TRACK',
    type: 'graphic',
    layer: 1,
    role: 'decoration',
    placement: {
      x: trackStartX,
      y: Math.round((midBeltY - 2) * scaleY),
      width: Math.max(10, trackEndX - trackStartX),
      height: Math.round(4 * scaleY),
      rotation: 0,
      opacity: 1,
    },
    content: {
      svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${trackEndX - trackStartX} 4" width="100%" height="100%" fill="none">
        <line x1="0" y1="2" x2="${trackEndX - trackStartX}" y2="2" stroke="#CBD5E1" stroke-width="3" stroke-dasharray="4 3" />
      </svg>`,
      colorMode: 'fixed',
      fill: '#CBD5E1',
      alt: 'Process Track',
    },
  });

  // 3. Step Cards, Icons, Titles, Descriptions
  steps.forEach((step) => {
    const n = step.stepNum;
    const defaultStep = PROCESS_LINEAR_HORIZONTAL_DEFAULT_STEPS[step.index % PROCESS_LINEAR_HORIZONTAL_DEFAULT_STEPS.length];

    const prevCard = prevBySlot.get(`STEP_${n}_CARD`) || prevBySlot.get(`STEP_${n}_SHAPE`);
    const prevIcon = prevBySlot.get(`STEP_${n}_ICON`);
    const prevTitle = prevBySlot.get(`STEP_${n}_TITLE`);
    const prevBody = prevBySlot.get(`STEP_${n}_BODY`);

    const cardColor = prevCard?.content?.fill || prevCard?.content?.color || step.color;

    // 3A. Standalone Card Graphic
    const cardSvg = buildLinearHorizontalCardSvg(step);
    newElements.push({
      id: prevCard?.id || newId(`grp-step-${n}-card`),
      slotId: `STEP_${n}_CARD`,
      type: 'graphic',
      layer: 2,
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
        alt: `Step ${n} Card`,
      },
    });

    // 3B. Standalone Icon Graphic
    const iconDeleted = prevBySlot.has(`STEP_${n}_ICON_DELETED`);
    if (!iconDeleted) {
      const iconSvg = buildLinearHorizontalIconSvg(step.iconPaths);
      newElements.push({
        id: prevIcon?.id || newId(`grp-step-${n}-icon`),
        slotId: `STEP_${n}_ICON`,
        type: 'graphic',
        layer: 5,
        role: 'decoration',
        placement: {
          x: Math.round(step.iconX * scaleX),
          y: Math.round(step.iconY * scaleY),
          width: Math.round(g.iconSize * scaleX),
          height: Math.round(g.iconSize * scaleY),
          rotation: 0,
          opacity: 1,
        },
        content: {
          svg: iconSvg,
          colorMode: 'recolorable',
          fill: prevIcon?.content?.fill || '#4A5568',
          color: prevIcon?.content?.color || '#4A5568',
          alt: `Step ${n} Icon`,
        },
      });
    }

    // 3C. STEP_n_TITLE Text Element
    const titleSlot = slots.find((s) => s.id === `STEP_${n}_TITLE`);
    const rawTitle =
      prevTitle?.content?.text ||
      prevTitle?.content?.html ||
      titleSlot?.placeholder_text;
    const titleText = isPlaceholderOrLatin(rawTitle) ? defaultStep.title : rawTitle;

    const textX = Math.round((step.cardX + 8) * scaleX);
    const textW = Math.round((step.cardW - 16) * scaleX);
    const titleY = Math.round((step.cardY + g.titleOffsetY) * scaleY);

    newElements.push({
      id: prevTitle?.id || newId(`txt-step-${n}-title`),
      slotId: `STEP_${n}_TITLE`,
      type: 'text',
      layer: 10,
      placement: {
        x: textX,
        y: titleY,
        width: textW,
        height: Math.round(g.titleH * scaleY),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: titleText,
        align: 'center',
        fontSize: 13,
        fontWeight: 800,
        colorRole: 'primary',
        color: prevTitle?.content?.color || cardColor,
        lineHeight: 1.15,
        clipToSlot: false,
      },
    });

    // 3D. STEP_n_BODY Text Element
    const bodySlot = slots.find((s) => s.id === `STEP_${n}_BODY`);
    const rawBody =
      prevBody?.content?.text ||
      prevBody?.content?.html ||
      bodySlot?.placeholder_text;
    const bodyText = isPlaceholderOrLatin(rawBody) ? defaultStep.body : rawBody;

    const bodyY = Math.round((step.cardY + g.bodyOffsetY) * scaleY);

    newElements.push({
      id: prevBody?.id || newId(`txt-step-${n}-body`),
      slotId: `STEP_${n}_BODY`,
      type: 'text',
      layer: 10,
      placement: {
        x: textX,
        y: bodyY,
        width: textW,
        height: Math.round(g.bodyH * scaleY),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: bodyText,
        align: 'center',
        fontSize: 11,
        fontWeight: 400,
        colorRole: 'muted',
        color: prevBody?.content?.color || '#64748B',
        lineHeight: 1.45,
        clipToSlot: false,
      },
    });
  });

  return newElements;
}

module.exports = {
  PROCESS_LINEAR_HORIZONTAL_GEOM,
  PROCESS_LINEAR_HORIZONTAL_DEFAULT_COLORS,
  isProcessLinearHorizontalLayout,
  calculateLinearHorizontalStepGeometries,
  buildLinearHorizontalCardSvg,
  buildLinearHorizontalIconSvg,
  layoutProcessLinearHorizontal,
};
