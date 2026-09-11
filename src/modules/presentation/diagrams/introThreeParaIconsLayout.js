/**
 * Intro Three Para Icons Layout Engine (Backend Server-Side Compiler)
 * Layout IDs:
 *  - intro_three_para_icons_v1: Vertical layout (3 stacked rows)
 *  - intro_three_para_icons_horizontal_v1: Horizontal layout (3 columns side-by-side)
 *
 * Modern, colorful, executive 3-pillar architecture.
 * Clean white canvas background (no heavy slide bg), featuring 3 distinct,
 * vibrant pillar cards with unique color themes, high-fidelity vector icons,
 * numbered badges, and structured typography.
 * Total elements: 12 (strictly <= 50) with complete placement coordinates.
 */

const INTRO_THREE_PARA_ICONS_HORIZONTAL_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Header Area
  badgeX: 44,
  badgeY: 22,
  badgeW: 190,
  badgeH: 22,

  headingX: 44,
  headingY: 48,
  headingW: 912,
  headingH: 34,

  subtitleX: 44,
  subtitleY: 84,
  subtitleW: 912,
  subtitleH: 22,

  // 3 Pillar Cards (Columns)
  cardY: 124,
  cardH: 396,
  cardW: 288,
  cardGap: 24,
  cardRadius: 16,

  // Inside Card Layout (Relative to card top-left)
  iconX: 20,
  iconY: 22,
  iconSize: 50,
  titleX: 20,
  titleY: 88,
  titleW: 248,
  titleH: 28,
  bodyX: 20,
  bodyY: 124,
  bodyW: 248,
  bodyH: 200,
};

const INTRO_THREE_PARA_ICONS_VERTICAL_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Header Area
  badgeX: 44,
  badgeY: 20,
  badgeW: 190,
  badgeH: 22,

  headingX: 44,
  headingY: 44,
  headingW: 912,
  headingH: 34,

  subtitleX: 44,
  subtitleY: 80,
  subtitleW: 912,
  subtitleH: 22,

  // 3 Stacked Rows
  cardX: 44,
  cardW: 912,
  cardH: 118,
  cardGap: 16,
  cardStartY: 116,
  cardRadius: 14,

  // Inside Card Layout (Relative to card top-left)
  titleX: 108,
  titleY: 52,
  titleW: 236,
  titleH: 30,

  bodyX: 375,
  bodyY: 24,
  bodyW: 512,
  bodyH: 70,
};

const INTRO_THREE_PILLARS_THEMES = [
  {
    index: '01',
    label: 'PILLAR 01 · STRATEGY',
    tag: 'STRATEGY',
    primary: '#2563EB',
    accent: '#3B82F6',
    tint: '#EFF6FF',
    border: '#DBEAFE',
    iconKind: 'strategy',
  },
  {
    index: '02',
    label: 'PILLAR 02 · INNOVATION',
    tag: 'INNOVATION',
    primary: '#7C3AED',
    accent: '#8B5CF6',
    tint: '#F5F3FF',
    border: '#EDE9FE',
    iconKind: 'innovation',
  },
  {
    index: '03',
    label: 'PILLAR 03 · ACCELERATION',
    tag: 'ACCELERATION',
    primary: '#0D9488',
    accent: '#14B8A6',
    tint: '#F0FDFA',
    border: '#CCFBF1',
    iconKind: 'growth',
  },
];

const INTRO_THREE_PARA_ICONS_DEFAULTS = {
  BADGE: 'STRATEGIC FOUNDATION',
  HEADING: 'Three pillars',
  SUBTITLE: 'Core principles driving long-term strategic execution and organizational alignment.',

  ROW_1_TITLE: 'Pillar 1: Strategy',
  ROW_1_BODY:
    'We help teams turn complex ideas into clear narratives that drive decisions and build momentum across the entire organization with quantifiable impact.',

  ROW_2_TITLE: 'Pillar 2: Innovation',
  ROW_2_BODY:
    'Our approach combines research, design, and storytelling so every initiative earns attention and every message lands with creative precision.',

  ROW_3_TITLE: 'Pillar 3: Acceleration',
  ROW_3_BODY:
    'From first draft to final delivery, we keep workflows agile, visual, and tightly aligned to your audience, growth milestones, and core vision.',
};

function isIntroThreeParaIconsLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase();
  return (
    id === 'intro_three_para_icons_v1' ||
    id === 'intro_three_para_icons_horizontal_v1' ||
    id === 'intro_three_para_icons'
  );
}

function isIntroThreeParaIconsHorizontal(layoutId, schema = {}) {
  const id = String(layoutId || schema?.layout_id || schema?.layoutId || '').toLowerCase();
  const variant = String(schema?.preview?.gridVariant || schema?.gridVariant || '').toLowerCase();
  return id.includes('horizontal') || variant === 'horizontal';
}

function renderPillarVectorIcon(iconKind, color, size = 50) {
  const s = size / 50;
  switch (iconKind) {
    case 'strategy':
      return `
        <g transform="scale(${s})">
          <circle cx="25" cy="25" r="16" fill="none" stroke="${color}" stroke-width="2.5" />
          <circle cx="25" cy="25" r="9" fill="none" stroke="${color}" stroke-width="2" />
          <circle cx="25" cy="25" r="3.5" fill="${color}" />
          <line x1="25" y1="5" x2="25" y2="9" stroke="${color}" stroke-width="2.5" stroke-linecap="round" />
          <line x1="25" y1="41" x2="25" y2="45" stroke="${color}" stroke-width="2.5" stroke-linecap="round" />
          <line x1="5" y1="25" x2="9" y2="25" stroke="${color}" stroke-width="2.5" stroke-linecap="round" />
          <line x1="41" y1="25" x2="45" y2="25" stroke="${color}" stroke-width="2.5" stroke-linecap="round" />
        </g>
      `;
    case 'innovation':
      return `
        <g transform="scale(${s})">
          <path d="M19 32h12M21 36h8M25 10a11 11 0 0 0-7 19c1.5 1.5 2 3 2 5h10c0-2 .5-3.5 2-5a11 11 0 0 0-7-19z" fill="none" stroke="${color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" />
          <line x1="25" y1="4" x2="25" y2="7" stroke="${color}" stroke-width="2" stroke-linecap="round" />
          <line x1="10" y1="14" x2="13" y2="16" stroke="${color}" stroke-width="2" stroke-linecap="round" />
          <line x1="40" y1="14" x2="37" y2="16" stroke="${color}" stroke-width="2" stroke-linecap="round" />
        </g>
      `;
    case 'growth':
    default:
      return `
        <g transform="scale(${s})">
          <path d="M25 8c-7 2-11 7-11 16 0 5 3 8 5 9l3-3 6 6 3-3c1-2 4-5 4-9 0-9-4-14-7-16z" fill="none" stroke="${color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" />
          <circle cx="25" cy="20" r="3" fill="${color}" />
          <path d="M14 24l-4 4 2 5 5-2 1-3" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" />
          <path d="M33 28l5 2 2-5-4-4-2 4" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" />
        </g>
      `;
  }
}

function buildPillarCardSvg(pillarIdx, width, height) {
  const theme = INTRO_THREE_PILLARS_THEMES[pillarIdx] || INTRO_THREE_PILLARS_THEMES[0];
  const { index, label, primary, accent, tint, border, iconKind } = theme;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <defs>
      <linearGradient id="pgrad-${pillarIdx}" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="${primary}" />
        <stop offset="100%" stop-color="${accent}" />
      </linearGradient>
      <filter id="pshad-${pillarIdx}" x="-6%" y="-4%" width="112%" height="114%" filterUnits="userSpaceOnUse">
        <feDropShadow dx="0" dy="4" stdDeviation="8" flood-color="#0F172A" flood-opacity="0.05" />
      </filter>
    </defs>

    <rect x="1" y="1" width="${width - 2}" height="${height - 2}" rx="16" fill="#FFFFFF" stroke="#E2E8F0" stroke-width="1.5" filter="url(#pshad-${pillarIdx})" />
    <path d="M 1 17 Q 1 1 17 1 L ${width - 17} 1 Q ${width - 1} 1 ${width - 1} 17 L ${width - 1} 7 L 1 7 Z" fill="url(#pgrad-${pillarIdx})" />

    <!-- Icon Bubble Container -->
    <g transform="translate(20, 22)">
      <rect width="50" height="50" rx="14" fill="${tint}" stroke="${border}" stroke-width="1.5" />
      ${renderPillarVectorIcon(iconKind, primary, 50)}
    </g>

    <!-- Number Pill Badge -->
    <g transform="translate(${width - 64}, 24)">
      <rect width="44" height="26" rx="13" fill="${tint}" stroke="${border}" stroke-width="1" />
      <text x="22" y="17" text-anchor="middle" fill="${primary}" font-size="12" font-weight="800" font-family="Inter, system-ui, sans-serif">${index}</text>
    </g>

    <!-- Bottom Tag -->
    <g transform="translate(20, ${height - 44})">
      <rect width="${width - 40}" height="28" rx="8" fill="${tint}" />
      <circle cx="14" cy="14" r="3.5" fill="${primary}" />
      <text x="26" y="18" fill="${primary}" font-size="10" font-weight="800" font-family="Inter, system-ui, sans-serif" letter-spacing="0.06em">${label}</text>
    </g>
  </svg>`;
}

function buildVerticalPillarCardSvg(pillarIdx, width, height) {
  const theme = INTRO_THREE_PILLARS_THEMES[pillarIdx] || INTRO_THREE_PILLARS_THEMES[0];
  const { index, tag, primary, tint, border, iconKind } = theme;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <defs>
      <filter id="vpshad-${pillarIdx}" x="-3%" y="-6%" width="106%" height="116%" filterUnits="userSpaceOnUse">
        <feDropShadow dx="0" dy="3" stdDeviation="6" flood-color="#0F172A" flood-opacity="0.04" />
      </filter>
    </defs>

    <!-- Card Background -->
    <rect x="1" y="1" width="${width - 2}" height="${height - 2}" rx="14" fill="#FFFFFF" stroke="#E2E8F0" stroke-width="1.5" filter="url(#vpshad-${pillarIdx})" />

    <!-- Left Accent Indicator Bar -->
    <rect x="1" y="14" width="4" height="${height - 28}" rx="2" fill="${primary}" />

    <!-- Left Icon Bubble -->
    <g transform="translate(20, 24)">
      <rect width="68" height="68" rx="16" fill="${tint}" stroke="${border}" stroke-width="1.5" />
      <g transform="translate(9, 9)">
        ${renderPillarVectorIcon(iconKind, primary, 50)}
      </g>
    </g>

    <!-- Number Pill + Tag -->
    <g transform="translate(108, 22)">
      <rect width="36" height="22" rx="6" fill="${tint}" stroke="${border}" stroke-width="1" />
      <text x="18" y="15" text-anchor="middle" fill="${primary}" font-size="11" font-weight="800" font-family="Inter, system-ui, sans-serif">${index}</text>
      <text x="46" y="15" fill="${primary}" font-size="10.5" font-weight="800" font-family="Inter, system-ui, sans-serif" letter-spacing="0.07em">${tag}</text>
    </g>

    <!-- Vertical Column Divider -->
    <line x1="355" y1="18" x2="355" y2="${height - 18}" stroke="#E2E8F0" stroke-width="1.2" stroke-dasharray="3 3" />
  </svg>`;
}

function layoutIntroThreeParaIcons(elements = [], schema = {}, palette = {}, canvas = {}) {
  const isHorizontal = isIntroThreeParaIconsHorizontal(schema?.layout_id || schema?.id || schema?.layoutId, schema);
  const g = isHorizontal ? INTRO_THREE_PARA_ICONS_HORIZONTAL_GEOM : INTRO_THREE_PARA_ICONS_VERTICAL_GEOM;

  const canvasW = canvas?.width || 1000;
  const canvasH = canvas?.height || 560;
  const scaleX = canvasW / g.viewW;
  const scaleY = canvasH / g.viewH;

  const safeElements = Array.isArray(elements) ? elements : [];
  const prevBySlot = new Map();
  safeElements.forEach((el) => {
    const sid = String(el.slotId || el.id || '').toUpperCase();
    if (sid) prevBySlot.set(sid, el);
  });

  const getPrevText = (slotId, fallback) => {
    const prev = prevBySlot.get(slotId);
    if (typeof prev?.content?.text === 'string' && prev.content.text.trim()) {
      return prev.content.text;
    }
    if (typeof prev?.content === 'string' && prev.content.trim()) {
      return prev.content;
    }
    return fallback;
  };

  const primaryColor = palette?.primary || '#2563EB';
  const textColor = palette?.text || '#0F172A';
  const mutedColor = palette?.muted || '#475569';

  const newElements = [];
  let seq = 0;
  const newId = (p) => `itp-${p}-${Date.now()}-${++seq}`;

  const pushElement = (el) => {
    if (!el.placement && el.rect) {
      el.placement = {
        x: el.rect.x,
        y: el.rect.y,
        width: el.rect.width,
        height: el.rect.height,
        rotation: 0,
        opacity: 1,
      };
    }
    newElements.push(el);
  };

  // 1. Top Category Badge
  pushElement({
    id: prevBySlot.get('TAG_BADGE')?.id || newId('badge'),
    type: 'text',
    slotId: 'TAG_BADGE',
    layer: 10,
    rect: {
      x: g.badgeX * scaleX,
      y: g.badgeY * scaleY,
      width: g.badgeW * scaleX,
      height: g.badgeH * scaleY,
    },
    content: {
      text: getPrevText('TAG_BADGE', INTRO_THREE_PARA_ICONS_DEFAULTS.BADGE),
      fontSize: 11,
      fontWeight: 800,
      color: primaryColor,
      letterSpacing: '0.08em',
      clipToSlot: false,
    },
  });

  // 2. Slide Main Heading
  pushElement({
    id: prevBySlot.get('HEADING')?.id || prevBySlot.get('INTRO')?.id || newId('heading'),
    type: 'text',
    slotId: 'HEADING',
    layer: 10,
    rect: {
      x: g.headingX * scaleX,
      y: g.headingY * scaleY,
      width: g.headingW * scaleX,
      height: g.headingH * scaleY,
    },
    content: {
      text:
        getPrevText('HEADING', '') ||
        getPrevText('INTRO', '') ||
        getPrevText('TITLE', '') ||
        INTRO_THREE_PARA_ICONS_DEFAULTS.HEADING,
      fontSize: 28,
      fontWeight: 800,
      color: textColor,
      clipToSlot: false,
    },
  });

  // 3. Subtitle
  pushElement({
    id: prevBySlot.get('SUBTITLE')?.id || newId('subtitle'),
    type: 'text',
    slotId: 'SUBTITLE',
    layer: 10,
    rect: {
      x: g.subtitleX * scaleX,
      y: g.subtitleY * scaleY,
      width: g.subtitleW * scaleX,
      height: g.subtitleH * scaleY,
    },
    content: {
      text:
        getPrevText('SUBTITLE', '') ||
        getPrevText('DESCRIPTION', '') ||
        INTRO_THREE_PARA_ICONS_DEFAULTS.SUBTITLE,
      fontSize: 13,
      fontWeight: 500,
      color: mutedColor,
      clipToSlot: false,
    },
  });

  // 4. 3 Vibrant Pillar Cards
  for (let i = 0; i < 3; i += 1) {
    const pNum = i + 1;

    let cardX, cardY, cardW, cardH, titleX, titleY, titleW, titleH, bodyX, bodyY, bodyW, bodyH;
    let cardSvg;

    if (isHorizontal) {
      cardX = g.badgeX + i * (g.cardW + g.cardGap);
      cardY = g.cardY;
      cardW = g.cardW;
      cardH = g.cardH;
      titleX = cardX + g.titleX;
      titleY = cardY + g.titleY;
      titleW = g.titleW;
      titleH = g.titleH;
      bodyX = cardX + g.bodyX;
      bodyY = cardY + g.bodyY;
      bodyW = g.bodyW;
      bodyH = g.bodyH;
      cardSvg = buildPillarCardSvg(i, g.cardW, g.cardH);
    } else {
      // Vertical Stacked Rows
      cardX = g.cardX;
      cardY = g.cardStartY + i * (g.cardH + g.cardGap);
      cardW = g.cardW;
      cardH = g.cardH;
      titleX = cardX + g.titleX;
      titleY = cardY + g.titleY;
      titleW = g.titleW;
      titleH = g.titleH;
      bodyX = cardX + g.bodyX;
      bodyY = cardY + g.bodyY;
      bodyW = g.bodyW;
      bodyH = g.bodyH;
      cardSvg = buildVerticalPillarCardSvg(i, g.cardW, g.cardH);
    }

    const cardSlotId = `ROW_${pNum}_CARD`;
    const titleSlotId = `ROW_${pNum}_TITLE`;
    const bodySlotId = `ROW_${pNum}_BODY`;

    pushElement({
      id: prevBySlot.get(cardSlotId)?.id || newId(`card-${pNum}`),
      type: 'graphic',
      slotId: cardSlotId,
      layer: 2,
      rect: {
        x: cardX * scaleX,
        y: cardY * scaleY,
        width: cardW * scaleX,
        height: cardH * scaleY,
      },
      content: {
        svg: cardSvg,
        format: 'svg',
        color: INTRO_THREE_PILLARS_THEMES[i].primary,
        fill: INTRO_THREE_PILLARS_THEMES[i].primary,
      },
    });

    // Pillar Title
    const titleText =
      getPrevText(titleSlotId, '') ||
      INTRO_THREE_PARA_ICONS_DEFAULTS[`ROW_${pNum}_TITLE`];

    pushElement({
      id: prevBySlot.get(titleSlotId)?.id || newId(`title-${pNum}`),
      type: 'text',
      slotId: titleSlotId,
      layer: 10,
      rect: {
        x: titleX * scaleX,
        y: titleY * scaleY,
        width: titleW * scaleX,
        height: titleH * scaleY,
      },
      content: {
        text: titleText,
        fontSize: isHorizontal ? 18 : 17,
        fontWeight: 800,
        color: textColor,
        clipToSlot: false,
      },
    });

    // Pillar Body Description
    const bodyText =
      getPrevText(bodySlotId, '') ||
      INTRO_THREE_PARA_ICONS_DEFAULTS[`ROW_${pNum}_BODY`];

    pushElement({
      id: prevBySlot.get(bodySlotId)?.id || newId(`body-${pNum}`),
      type: 'text',
      slotId: bodySlotId,
      layer: 10,
      rect: {
        x: bodyX * scaleX,
        y: bodyY * scaleY,
        width: bodyW * scaleX,
        height: bodyH * scaleY,
      },
      content: {
        text: bodyText,
        fontSize: 13.5,
        fontWeight: 400,
        color: mutedColor,
        lineHeight: 1.5,
        clipToSlot: false,
      },
    });
  }

  return newElements;
}

module.exports = {
  INTRO_THREE_PARA_ICONS_HORIZONTAL_GEOM,
  INTRO_THREE_PARA_ICONS_VERTICAL_GEOM,
  INTRO_THREE_PILLARS_THEMES,
  INTRO_THREE_PARA_ICONS_DEFAULTS,
  isIntroThreeParaIconsLayout,
  isIntroThreeParaIconsHorizontal,
  buildPillarCardSvg,
  buildVerticalPillarCardSvg,
  layoutIntroThreeParaIcons,
};
