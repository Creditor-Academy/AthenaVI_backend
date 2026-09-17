/**
 * Process Linear Horizontal ("process_linear_horti") Layout (Backend)
 * Layout IDs: process_linear_horizontal_v2, process_linner_horti_v1, process_linner_horti_four_v1, process_linear_horti, process_linear_v1
 *
 * Visual Reference:
 *  - Centered Header: Title + Subtitle description
 *  - 5 Horizontal Steps with double-circle badge:
 *      * Colored thick outer ring
 *      * Inner solid white circle with themed vector icon
 *      * Horizontal connector line extending to next circle in step's accent color
 *      * Orbital arc curving around the lower-right quadrant (~80° arc)
 *      * Small solid circular dot at the end of the arc
 *  - Step Title ("ADD TEXT HERE") in step accent color, uppercase, bold
 *  - Step Description (3-4 lines centered text) in muted body text
 */

const PROCESS_LINEAR_HORTI_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Header
  headingX: 100,
  headingY: 30,
  headingW: 800,
  headingH: 40,

  subtitleX: 120,
  subtitleY: 74,
  subtitleW: 760,
  subtitleH: 46,

  // Nodes
  cy: 228,
  rOuter: 46,
  rInner: 34,
  rArc: 55,
  arcAngleDeg: 78,
  dotRadius: 3.5,

  // Icons
  iconSize: 28,

  // Text below
  titleOffsetY: 72,
  titleW: 172,
  titleH: 26,
  bodyOffsetY: 102,
  bodyW: 172,
  bodyH: 88,
};

const PROCESS_LINEAR_HORTI_DEFAULT_COLORS = [
  '#54B2C8', // 1: Cyan / Teal
  '#E85B4E', // 2: Coral Red
  '#4E637D', // 3: Slate Blue / Navy
  '#EAB327', // 4: Warm Golden Yellow
  '#80B58E', // 5: Sage Green
  '#9333EA', // 6: Deep Purple
  '#EA580C', // 7: Vibrant Amber
];

const PROCESS_LINEAR_HORTI_DEFAULT_STEPS = [
  {
    title: 'Discovery',
    body: 'Identify core goals, understand stakeholder needs, and align the scope.',
  },
  {
    title: 'Strategy',
    body: 'Formulate strategic roadmaps, allocate resources, and set milestones.',
  },
  {
    title: 'Concept & Design',
    body: 'Explore creative ideas, build rapid prototypes, and refine architectures.',
  },
  {
    title: 'Execution',
    body: 'Build robust features iteratively, test quality, and ensure excellence.',
  },
  {
    title: 'Launch & Success',
    body: 'Deploy with confidence, track key metrics, and celebrate success.',
  },
];

function isPlaceholderOrLatinText(str) {
  const s = String(str || '').toLowerCase().trim();
  if (!s) return true;
  return (
    s === 'add text here' ||
    s === 'text goes here' ||
    s.includes('at vero eos') ||
    s.includes('lorem ipsum') ||
    s.includes('accus qui amus') ||
    s.includes('dignissimos ducim')
  );
}

function isProcessLinearHortiLayout(layoutId) {
  const s = String(layoutId || '').toLowerCase().trim();
  return (
    s === 'process_linner_horti_v1' ||
    s === 'process_linear_horti' ||
    s === 'process_linear_v1'
  );
}

const PROCESS_LINEAR_HORTI_ICON_PATHS = [
  // 1: Handshake
  `
    <path d="m11 17 2 2a1 1 0 0 0 1.4 0l4.3-4.3a1 1 0 0 0 0-1.4l-3-3a1 1 0 0 0-1.4 0L13 11.6"/>
    <path d="m14 8 2.5-2.5a1 1 0 0 1 1.4 0l3.6 3.6a1 1 0 0 1 0 1.4L18 14"/>
    <path d="m10 14-1.3 1.3a1 1 0 0 1-1.4 0L3.7 11.7a1 1 0 0 1 0-1.4L8 6a1 1 0 0 1 1.4 0l4 4"/>
    <path d="m7 11 4.5 4.5"/>
  `,
  // 2: Briefcase
  `
    <rect width="18" height="13" x="3" y="7" rx="2.5"/>
    <path d="M15 20V5a2 2 0 0 0-2-2h-2a2 2 0 0 0-2 2v15"/>
    <path d="M10 11h4"/>
  `,
  // 3: Lightbulb
  `
    <path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5"/>
    <path d="M9 18h6"/>
    <path d="M10 21h4"/>
  `,
  // 4: Growth / Person climbing stairs
  `
    <path d="M4 20h4v-4h4v-4h4V8h4"/>
    <circle cx="10" cy="5" r="2"/>
    <path d="m7 13 3-3 2 2 3-4"/>
  `,
  // 5: Medal / Rosette Award Ribbon
  `
    <circle cx="12" cy="8" r="5.5"/>
    <path d="M15.5 13 17 22l-5-2.8-5 2.8 1.5-9"/>
    <circle cx="12" cy="8" r="2.5" fill="currentColor" opacity="0.35"/>
  `,
];

function calculateProcessHortiStepGeometries(stepCount = 5) {
  const g = PROCESS_LINEAR_HORTI_GEOM;
  const n = Math.max(2, Math.min(7, stepCount));
  const padX = n <= 3 ? 160 : n <= 4 ? 100 : 70;
  const usableW = g.viewW - padX * 2;
  const stepGap = usableW / (n - 1);

  const rad = (g.arcAngleDeg * Math.PI) / 180;
  const arcDx = g.rArc * Math.cos(rad);
  const arcDy = g.rArc * Math.sin(rad);

  const steps = [];
  for (let i = 0; i < n; i += 1) {
    const cx = Math.round(padX + i * stepGap);
    const isLast = i === n - 1;
    const nextCx = isLast ? null : Math.round(padX + (i + 1) * stepGap);

    const x = cx - g.rOuter;
    const y = g.cy - g.rOuter;
    const connectorEndX = isLast ? cx + g.rArc + 2 : nextCx - g.rOuter;
    const w = Math.max(g.rOuter * 2, connectorEndX - x);
    const h = Math.round(g.rOuter + arcDy + g.dotRadius + 6);

    steps.push({
      index: i,
      stepNum: i + 1,
      cx,
      cy: g.cy,
      isLast,
      nextCx,
      x,
      y,
      w,
      h,
      localCx: g.rOuter,
      localCy: g.rOuter,
      connectorEndX: w,
      arcDx,
      arcDy,
      color: PROCESS_LINEAR_HORTI_DEFAULT_COLORS[i % PROCESS_LINEAR_HORTI_DEFAULT_COLORS.length],
      iconPaths: PROCESS_LINEAR_HORTI_ICON_PATHS[i % PROCESS_LINEAR_HORTI_ICON_PATHS.length],
    });
  }

  return steps;
}

function buildProcessHortiStepSvg(step) {
  const g = PROCESS_LINEAR_HORTI_GEOM;
  const { localCx, localCy, w, h, isLast, arcDx, arcDy } = step;

  const lineEndX = isLast ? localCx + g.rArc : w;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" fill="none">
    <line x1="${localCx + g.rOuter}" y1="${localCy}" x2="${lineEndX}" y2="${localCy}" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" />
    <path d="M ${localCx + g.rArc} ${localCy} A ${g.rArc} ${g.rArc} 0 0 1 ${localCx + arcDx} ${localCy + arcDy}" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" />
    <circle cx="${localCx + arcDx}" cy="${localCy + arcDy}" r="${g.dotRadius}" fill="currentColor" />
    <circle cx="${localCx}" cy="${localCy}" r="${g.rOuter}" fill="currentColor" />
    <circle cx="${localCx}" cy="${localCy}" r="${g.rInner}" fill="#FFFFFF" />
  </svg>`;
}

function buildProcessHortiIconSvg(iconPaths) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="100%" height="100%" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    ${iconPaths}
  </svg>`;
}

function layoutProcessLinearHorti(elements = [], schema = {}, palette = {}, canvas = {}) {
  const g = PROCESS_LINEAR_HORTI_GEOM;
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
  const steps = calculateProcessHortiStepGeometries(stepCount);

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
    'PROCESS FLOW INFOGRAPHICS';

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
      color: prevHeading?.content?.color || '#1E293B',
      lineHeight: 1.15,
      clipToSlot: false,
    },
  });

  // 2. SUBTITLE
  const prevSubtitle = prevBySlot.get('SUBTITLE');
  const subtitleSlot = slots.find((s) => s.id === 'SUBTITLE');
  if (prevSubtitle || subtitleSlot) {
    const rawSubtitle =
      prevSubtitle?.content?.text ||
      prevSubtitle?.content?.html ||
      subtitleSlot?.placeholder_text;
    const subtitleText = isPlaceholderOrLatinText(rawSubtitle)
      ? 'A streamlined step-by-step roadmap from initial discovery through successful execution and delivery.'
      : rawSubtitle;

    newElements.push({
      id: prevSubtitle?.id || newId('txt-subtitle'),
      slotId: 'SUBTITLE',
      type: 'text',
      layer: 10,
      placement: {
        x: Math.round(g.subtitleX * scaleX),
        y: Math.round(g.subtitleY * scaleY),
        width: Math.round(g.subtitleW * scaleX),
        height: Math.round(g.subtitleH * scaleY),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: subtitleText,
        align: 'center',
        fontSize: 12.5,
        fontWeight: 400,
        colorRole: 'muted',
        color: prevSubtitle?.content?.color || '#64748B',
        lineHeight: 1.45,
        clipToSlot: false,
      },
    });
  }

  // 3. Step Badges, Icons, Titles, Descriptions
  steps.forEach((step) => {
    const n = step.stepNum;

    const prevShape = prevBySlot.get(`STEP_${n}_SHAPE`) || prevBySlot.get(`STEP_${n}_NODE`) || prevBySlot.get(`STEP_${n}_RING`);
    const prevIcon = prevBySlot.get(`STEP_${n}_ICON`);
    const prevTitle = prevBySlot.get(`STEP_${n}_TITLE`);
    const prevBody = prevBySlot.get(`STEP_${n}_BODY`);

    const shapeColor = prevShape?.content?.fill || prevShape?.content?.color || step.color;
    const iconColor = prevIcon?.content?.fill || prevIcon?.content?.color || shapeColor;

    // 3A. Standalone Badge Graphic
    const badgeSvg = buildProcessHortiStepSvg(step);
    newElements.push({
      id: prevShape?.id || newId(`grp-step-${n}-shape`),
      slotId: `STEP_${n}_SHAPE`,
      type: 'graphic',
      layer: 2,
      role: 'decoration',
      placement: {
        x: Math.round(step.x * scaleX),
        y: Math.round(step.y * scaleY),
        width: Math.round(step.w * scaleX),
        height: Math.round(step.h * scaleY),
        rotation: 0,
        opacity: 1,
      },
      content: {
        svg: badgeSvg,
        colorMode: 'recolorable',
        fill: shapeColor,
        color: shapeColor,
        colorRole: 'primary',
        alt: `Step ${n} Process Ring`,
      },
    });

    // 3B. Standalone Icon Graphic
    const iconDeleted = prevBySlot.has(`STEP_${n}_ICON_DELETED`);
    if (!iconDeleted) {
      const iconX = Math.round(step.cx - g.iconSize / 2);
      const iconY = Math.round(step.cy - g.iconSize / 2);
      const iconSvg = buildProcessHortiIconSvg(step.iconPaths);

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

    const defaultStep = PROCESS_LINEAR_HORTI_DEFAULT_STEPS[step.index % PROCESS_LINEAR_HORTI_DEFAULT_STEPS.length];

    // 3C. STEP_n_TITLE Text Element
    const titleSlot = slots.find((s) => s.id === `STEP_${n}_TITLE`);
    const rawTitle =
      prevTitle?.content?.text ||
      prevTitle?.content?.html ||
      titleSlot?.placeholder_text;
    const titleText = isPlaceholderOrLatinText(rawTitle) ? defaultStep.title : rawTitle;

    const titleX = Math.round(step.cx - g.titleW / 2);
    const titleY = Math.round(step.cy + g.titleOffsetY);

    newElements.push({
      id: prevTitle?.id || newId(`txt-step-${n}-title`),
      slotId: `STEP_${n}_TITLE`,
      type: 'text',
      layer: 10,
      placement: {
        x: Math.round(titleX * scaleX),
        y: Math.round(titleY * scaleY),
        width: Math.round(g.titleW * scaleX),
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
        color: prevTitle?.content?.color || shapeColor,
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
    const bodyText = isPlaceholderOrLatinText(rawBody) ? defaultStep.body : rawBody;

    const bodyX = Math.round(step.cx - g.bodyW / 2);
    const bodyY = Math.round(step.cy + g.bodyOffsetY);

    newElements.push({
      id: prevBody?.id || newId(`txt-step-${n}-body`),
      slotId: `STEP_${n}_BODY`,
      type: 'text',
      layer: 10,
      placement: {
        x: Math.round(bodyX * scaleX),
        y: Math.round(bodyY * scaleY),
        width: Math.round(g.bodyW * scaleX),
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
  PROCESS_LINEAR_HORTI_GEOM,
  PROCESS_LINEAR_HORTI_DEFAULT_COLORS,
  isProcessLinearHortiLayout,
  calculateProcessHortiStepGeometries,
  buildProcessHortiStepSvg,
  buildProcessHortiIconSvg,
  layoutProcessLinearHorti,
};
