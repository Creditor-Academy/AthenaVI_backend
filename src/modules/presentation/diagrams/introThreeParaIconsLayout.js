/**
 * Intro Three Para Icons (backend)
 * intro_three_para_icons_v1 | intro_three_para_icons_horizontal_v1
 */

const INTRO_THREE_PARA_ICONS_HORIZONTAL_GEOM = {
  viewW: 1000,
  viewH: 560,
  badgeX: 40,
  badgeY: 22,
  badgeW: 220,
  badgeH: 18,
  headingX: 40,
  headingY: 44,
  headingW: 920,
  headingH: 34,
  subtitleX: 40,
  subtitleY: 82,
  subtitleW: 920,
  subtitleH: 22,
  cardY: 118,
  cardH: 406,
  cardW: 296,
  cardGap: 16,
  titleX: 24,
  titleY: 132,
  titleW: 248,
  titleH: 44,
  bodyX: 24,
  bodyY: 184,
  bodyW: 248,
  bodyH: 196,
};

const INTRO_THREE_PARA_ICONS_VERTICAL_GEOM = {
  viewW: 1000,
  viewH: 560,
  badgeX: 40,
  badgeY: 20,
  badgeW: 220,
  badgeH: 18,
  headingX: 40,
  headingY: 42,
  headingW: 920,
  headingH: 34,
  subtitleX: 40,
  subtitleY: 80,
  subtitleW: 920,
  subtitleH: 22,
  cardX: 40,
  cardW: 920,
  cardH: 128,
  cardGap: 14,
  cardStartY: 114,
  titleX: 148,
  titleY: 28,
  titleW: 280,
  titleH: 28,
  bodyX: 148,
  bodyY: 62,
  bodyW: 732,
  bodyH: 48,
};

const INTRO_THREE_PARA_ICONS_PALETTE = {
  primary: '#148A80',
  textDark: '#111827',
  textMuted: '#6B7280',
};

const INTRO_THREE_PILLARS_THEMES = [
  { index: '01', iconKind: 'strategy' },
  { index: '02', iconKind: 'innovation' },
  { index: '03', iconKind: 'growth' },
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

function renderPillarVectorIcon(iconKind, color = 'currentColor', size = 28) {
  const s = size / 28;
  switch (iconKind) {
    case 'strategy':
      return `<g transform="scale(${s})" fill="none" stroke="${color}" stroke-width="1.8" stroke-linecap="round">
        <circle cx="14" cy="14" r="9" /><circle cx="14" cy="14" r="4" /><circle cx="14" cy="14" r="1.4" fill="${color}" stroke="none" />
        <path d="M14 2.5v2.2M14 23.3v2.2M2.5 14h2.2M23.3 14h2.2" />
      </g>`;
    case 'innovation':
      return `<g transform="scale(${s})" fill="none" stroke="${color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M10 20h8M11 23h6M14 4.5a7 7 0 0 0-4.6 12c.9 1 1.3 2 1.3 3.2h6.6c0-1.2.4-2.2 1.3-3.2A7 7 0 0 0 14 4.5z" />
      </g>`;
    case 'growth':
    default:
      return `<g transform="scale(${s})" fill="none" stroke="${color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
        <path d="M5 20.5l5.5-5.5 3.2 3.2L23 9" /><path d="M16.5 9H23v6.5" />
      </g>`;
  }
}

function buildPillarCardSvg(pillarIdx, width, height) {
  const theme = INTRO_THREE_PILLARS_THEMES[pillarIdx] || INTRO_THREE_PILLARS_THEMES[0];
  const cx = 40;
  const cy = 48;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <rect width="${width}" height="${height}" fill="#FBFBFA" />
    <rect x="0" y="0" width="${width}" height="3" fill="currentColor" />
    <circle cx="${cx}" cy="${cy}" r="22" fill="none" stroke="currentColor" stroke-width="1.4" />
    <g transform="translate(${cx - 14}, ${cy - 14})">${renderPillarVectorIcon(theme.iconKind)}</g>
    <text x="24" y="96" fill="currentColor" font-size="22" font-weight="800" font-family="Inter, system-ui, sans-serif">${theme.index}</text>
    <rect x="24" y="${height - 1}" width="${width - 48}" height="1" fill="currentColor" fill-opacity="0.14" />
  </svg>`;
}

function buildVerticalPillarCardSvg(pillarIdx, width, height) {
  const theme = INTRO_THREE_PILLARS_THEMES[pillarIdx] || INTRO_THREE_PILLARS_THEMES[0];
  const cy = height / 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <rect width="${width}" height="${height}" fill="#FBFBFA" />
    <rect x="0" y="18" width="3" height="${height - 36}" rx="1.5" fill="currentColor" />
    <circle cx="64" cy="${cy}" r="26" fill="none" stroke="currentColor" stroke-width="1.4" />
    <g transform="translate(50, ${cy - 14})">${renderPillarVectorIcon(theme.iconKind)}</g>
    <text x="108" y="36" fill="currentColor" font-size="13" font-weight="800" font-family="Inter, system-ui, sans-serif">${theme.index}</text>
    <rect x="0" y="${height - 1}" width="${width}" height="1" fill="currentColor" fill-opacity="0.14" />
  </svg>`;
}

function resolveStoredColor(el, fallback) {
  const fill = el?.content?.fill;
  if (typeof fill === 'string' && fill && fill !== 'none' && fill !== 'transparent') return fill;
  if (fill && typeof fill === 'object' && fill.color) return fill.color;
  return fallback;
}

function layoutIntroThreeParaIcons(docOrElements = [], schema = {}, palette = {}, canvas = {}) {
  const isHorizontal = isIntroThreeParaIconsHorizontal(schema?.layout_id || schema?.id || schema?.layoutId, schema);
  const g = isHorizontal ? INTRO_THREE_PARA_ICONS_HORIZONTAL_GEOM : INTRO_THREE_PARA_ICONS_VERTICAL_GEOM;
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1000;
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 560;
  const scaleX = canvasW / g.viewW;
  const scaleY = canvasH / g.viewH;
  const pal = palette?.primary ? palette : (palette?.palette || palette || {});
  const accent = pal.primary || pal.accent || INTRO_THREE_PARA_ICONS_PALETTE.primary;
  const textColor = pal.text || INTRO_THREE_PARA_ICONS_PALETTE.textDark;
  const mutedColor = pal.muted || INTRO_THREE_PARA_ICONS_PALETTE.textMuted;

  const prevBySlot = new Map();
  elements.forEach((el) => {
    const sid = String(el.slotId || el.id || '').toUpperCase();
    if (sid) prevBySlot.set(sid, el);
  });

  const getPrevText = (slotId, fallback) => {
    const prev = prevBySlot.get(slotId);
    const txt = prev?.content?.text || prev?.text;
    if (txt && String(txt).trim()) return String(txt).trim();
    return fallback;
  };

  const newElements = [];
  const pushText = (config) => {
    const placement = {
      x: Math.round(config.x),
      y: Math.round(config.y),
      width: Math.max(1, Math.round(config.width)),
      height: Math.max(1, Math.round(config.height)),
      rotation: 0,
      opacity: 1,
    };
    newElements.push({
      id: config.id,
      type: 'text',
      slotId: config.slotId,
      role: config.role || 'body',
      layer: 10,
      placement,
      rect: { ...placement },
      content: {
        text: config.text,
        fontSize: config.fontSize,
        fontWeight: config.fontWeight || 500,
        color: config.color,
        align: 'left',
        lineHeight: config.lineHeight || 1.25,
        letterSpacing: config.letterSpacing || 'normal',
        clipToSlot: true,
        maxLines: config.maxLines || 2,
      },
    });
  };
  const pushGraphic = (config) => {
    const prev = prevBySlot.get(config.slotId);
    const fill = resolveStoredColor(prev, accent);
    const placement = {
      x: Math.round(config.x),
      y: Math.round(config.y),
      width: Math.max(1, Math.round(config.width)),
      height: Math.max(1, Math.round(config.height)),
      rotation: 0,
      opacity: 1,
    };
    newElements.push({
      id: config.id,
      type: 'graphic',
      slotId: config.slotId,
      role: 'decoration',
      layer: 2,
      placement,
      rect: { ...placement },
      content: {
        svg: config.svg,
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill,
        stroke: fill,
      },
    });
  };

  pushText({
    id: prevBySlot.get('TAG_BADGE')?.id || 'itp_badge',
    slotId: 'TAG_BADGE',
    role: 'caption',
    text: String(getPrevText('TAG_BADGE', INTRO_THREE_PARA_ICONS_DEFAULTS.BADGE)).toUpperCase(),
    x: g.badgeX * scaleX,
    y: g.badgeY * scaleY,
    width: g.badgeW * scaleX,
    height: g.badgeH * scaleY,
    fontSize: 11,
    fontWeight: 700,
    color: accent,
    letterSpacing: '0.16em',
    maxLines: 1,
  });

  pushText({
    id: prevBySlot.get('HEADING')?.id || prevBySlot.get('INTRO')?.id || 'itp_heading',
    slotId: 'HEADING',
    role: 'heading',
    text:
      getPrevText('HEADING', '') ||
      getPrevText('INTRO', '') ||
      getPrevText('TITLE', '') ||
      INTRO_THREE_PARA_ICONS_DEFAULTS.HEADING,
    x: g.headingX * scaleX,
    y: g.headingY * scaleY,
    width: g.headingW * scaleX,
    height: g.headingH * scaleY,
    fontSize: 28,
    fontWeight: 800,
    color: textColor,
    maxLines: 1,
  });

  pushText({
    id: prevBySlot.get('SUBTITLE')?.id || 'itp_subtitle',
    slotId: 'SUBTITLE',
    role: 'subheading',
    text: getPrevText('SUBTITLE', '') || getPrevText('DESCRIPTION', '') || INTRO_THREE_PARA_ICONS_DEFAULTS.SUBTITLE,
    x: g.subtitleX * scaleX,
    y: g.subtitleY * scaleY,
    width: g.subtitleW * scaleX,
    height: g.subtitleH * scaleY,
    fontSize: 13,
    fontWeight: 500,
    color: mutedColor,
    maxLines: 1,
  });

  for (let i = 0; i < 3; i += 1) {
    const pNum = i + 1;
    let cardX;
    let cardY;
    if (isHorizontal) {
      cardX = g.badgeX + i * (g.cardW + g.cardGap);
      cardY = g.cardY;
    } else {
      cardX = g.cardX;
      cardY = g.cardStartY + i * (g.cardH + g.cardGap);
    }

    const cardSlotId = `ROW_${pNum}_CARD`;
    const titleSlotId = `ROW_${pNum}_TITLE`;
    const bodySlotId = `ROW_${pNum}_BODY`;
    const cardSvg = isHorizontal
      ? buildPillarCardSvg(i, g.cardW, g.cardH)
      : buildVerticalPillarCardSvg(i, g.cardW, g.cardH);

    pushGraphic({
      id: prevBySlot.get(cardSlotId)?.id || `itp_card_${pNum}`,
      slotId: cardSlotId,
      svg: cardSvg,
      x: cardX * scaleX,
      y: cardY * scaleY,
      width: g.cardW * scaleX,
      height: g.cardH * scaleY,
    });

    pushText({
      id: prevBySlot.get(titleSlotId)?.id || `itp_title_${pNum}`,
      slotId: titleSlotId,
      role: 'heading',
      text: getPrevText(titleSlotId, '') || INTRO_THREE_PARA_ICONS_DEFAULTS[`ROW_${pNum}_TITLE`],
      x: (cardX + g.titleX) * scaleX,
      y: (cardY + g.titleY) * scaleY,
      width: g.titleW * scaleX,
      height: g.titleH * scaleY,
      fontSize: isHorizontal ? 18 : 17,
      fontWeight: 800,
      color: textColor,
      maxLines: 2,
    });

    pushText({
      id: prevBySlot.get(bodySlotId)?.id || `itp_body_${pNum}`,
      slotId: bodySlotId,
      role: 'body',
      text: getPrevText(bodySlotId, '') || INTRO_THREE_PARA_ICONS_DEFAULTS[`ROW_${pNum}_BODY`],
      x: (cardX + g.bodyX) * scaleX,
      y: (cardY + g.bodyY) * scaleY,
      width: g.bodyW * scaleX,
      height: g.bodyH * scaleY,
      fontSize: 13.5,
      fontWeight: 400,
      color: mutedColor,
      lineHeight: 1.45,
      maxLines: isHorizontal ? 8 : 3,
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
