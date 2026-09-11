/**
 * Grid Bento Three Layout Engine (Backend Server-Side Compiler)
 * Layout IDs:
 *  - grid_bento_three_v1
 *  - grid_bento_three
 *  - grid_three_asymmetric_v1
 *
 * Executive Bento Showcase:
 *  - Top Slide Header:
 *    - Pill Badge ("CURATED SHOWCASE")
 *    - Main Heading ("Three-part bento overview")
 *    - Subtitle ("Key flagship highlights and tailored solutions.")
 *  - 3 Bento Cards (matching reference layout):
 *    - Card 1 (Top Hero - Full Width):
 *      - Left: Category Tag ("FOOD & CULINARY"), Headline ("Wake Up and Smell the Coffee"), Description, CTA Pill ("Learn more →")
 *      - Right: Clean layout visual placeholder container (soft teal tint, no external photos yet)
 *    - Card 2 (Bottom Left - Half Width):
 *      - Category Tag ("ECO & SUSTAINABILITY"), Headline ("Purify the air in your home"), Description, CTA Pill ("Learn more →")
 *      - Right: Clean layout visual placeholder container (soft sky blue tint)
 *    - Card 3 (Bottom Right - Half Width):
 *      - Category Tag ("HEALTH & WELLNESS"), Headline ("Experience the fluidity of the gel"), Description, CTA Pill ("Learn more →")
 *      - Right: Clean layout visual placeholder container (soft blush rose tint)
 *  - Total Elements: ~21 elements (strictly <= 50) with complete placement coordinates.
 */

const GRID_BENTO_THREE_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Slide Header Area
  badgeX: 44,
  badgeY: 20,
  badgeW: 190,
  badgeH: 22,

  headingX: 44,
  headingY: 46,
  headingW: 912,
  headingH: 34,

  subtitleX: 44,
  subtitleY: 82,
  subtitleW: 912,
  subtitleH: 22,

  // Card 1: Top Hero Card (Full Width)
  card1: {
    x: 44,
    y: 116,
    w: 912,
    h: 188,
    radius: 18,
    // Content left
    tagX: 68,
    tagY: 136,
    tagW: 160,
    tagH: 22,
    titleX: 68,
    titleY: 164,
    titleW: 470,
    titleH: 30,
    bodyX: 68,
    bodyY: 198,
    bodyW: 470,
    bodyH: 42,
    ctaX: 68,
    ctaY: 248,
    ctaW: 120,
    ctaH: 34,
    // Visual placeholder right
    visualX: 560,
    visualY: 130,
    visualW: 376,
    visualH: 160,
    visualRadius: 14,
  },

  // Card 2: Bottom Left Card (Half Width)
  card2: {
    x: 44,
    y: 318,
    w: 448,
    h: 216,
    radius: 18,
    tagX: 66,
    tagY: 336,
    tagW: 150,
    tagH: 22,
    titleX: 66,
    titleY: 364,
    titleW: 224,
    titleH: 48,
    bodyX: 66,
    bodyY: 418,
    bodyW: 224,
    bodyH: 50,
    ctaX: 66,
    ctaY: 478,
    ctaW: 114,
    ctaH: 32,
    visualX: 304,
    visualY: 334,
    visualW: 172,
    visualH: 184,
    visualRadius: 14,
  },

  // Card 3: Bottom Right Card (Half Width)
  card3: {
    x: 508,
    y: 318,
    w: 448,
    h: 216,
    radius: 18,
    tagX: 530,
    tagY: 336,
    tagW: 150,
    tagH: 22,
    titleX: 530,
    titleY: 364,
    titleW: 224,
    titleH: 48,
    bodyX: 530,
    bodyY: 418,
    bodyW: 224,
    bodyH: 50,
    ctaX: 530,
    ctaY: 478,
    ctaW: 114,
    ctaH: 32,
    visualX: 768,
    visualY: 334,
    visualW: 172,
    visualH: 184,
    visualRadius: 14,
  },
};

const GRID_BENTO_THEMES = [
  {
    tag: 'FOOD & CULINARY',
    primary: '#0D9488', // Emerald/Teal
    accent: '#14B8A6',
    tint: '#F0FDFA',
    border: '#CCFBF1',
    cardBg: '#FFFFFF',
    visualGradStart: '#E6FFFA',
    visualGradEnd: '#CCFBF1',
  },
  {
    tag: 'ECO & SUSTAINABILITY',
    primary: '#0284C7', // Sky Blue
    accent: '#38BDF8',
    tint: '#F0F9FF',
    border: '#BAE6FD',
    cardBg: '#FFFFFF',
    visualGradStart: '#F0F9FF',
    visualGradEnd: '#E0F2FE',
  },
  {
    tag: 'HEALTH & WELLNESS',
    primary: '#E11D48', // Rose / Blush
    accent: '#FB7185',
    tint: '#FFF1F2',
    border: '#FECDD3',
    cardBg: '#FFFFFF',
    visualGradStart: '#FFF1F2',
    visualGradEnd: '#FFE4E6',
  },
];

const GRID_BENTO_THREE_DEFAULTS = {
  BADGE: 'CURATED SHOWCASE',
  HEADING: 'Three-part bento overview',
  SUBTITLE: 'Flagship product experiences, botanical purity, and sensory wellness highlights.',

  CARD_1_TAG: 'FOOD & CULINARY',
  CARD_1_TITLE: 'Wake Up and Smell the Coffee',
  CARD_1_BODY: 'Artisan morning rituals crafted with sustainably harvested beans and rich aromatic depth.',
  CARD_1_CTA: 'Learn more →',

  CARD_2_TAG: 'ECO & SUSTAINABILITY',
  CARD_2_TITLE: 'Purify the air in your home',
  CARD_2_BODY: 'Clean living botanicals designed to cultivate restorative atmospheres and indoor vitality.',
  CARD_2_CTA: 'Learn more →',

  CARD_3_TAG: 'HEALTH & WELLNESS',
  CARD_3_TITLE: 'Experience the fluidity of the gel',
  CARD_3_BODY: 'Lightweight, ultra-hydrating formulations engineered for daily cellular renewal.',
  CARD_3_CTA: 'Learn more →',
};

function isGridBentoThreeLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase();
  return (
    id === 'grid_bento_three_v1' ||
    id === 'grid_bento_three' ||
    id === 'grid_three_asymmetric_v1'
  );
}

function buildBentoCardShapeSvg(cardIdx, width, height, radius = 18) {
  const theme = GRID_BENTO_THEMES[cardIdx] || GRID_BENTO_THEMES[0];
  const { primary, tint, border } = theme;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <defs>
      <linearGradient id="bgrad-s-${cardIdx}" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#FFFFFF" />
        <stop offset="70%" stop-color="#FFFFFF" />
        <stop offset="100%" stop-color="${tint}" stop-opacity="0.8" />
      </linearGradient>
      <filter id="bshad-s-${cardIdx}" x="-4%" y="-6%" width="108%" height="116%" filterUnits="userSpaceOnUse">
        <feDropShadow dx="0" dy="4" stdDeviation="8" flood-color="#0F172A" flood-opacity="0.04" />
      </filter>
    </defs>
    <rect x="1.5" y="1.5" width="${width - 3}" height="${height - 3}" rx="${radius}" fill="url(#bgrad-s-${cardIdx})" stroke="${border}" stroke-width="1.5" filter="url(#bshad-s-${cardIdx})" />
    <path d="M 2 20 Q 2 2 20 2 L 60 2 Q 2 2 2 60 Z" fill="${primary}" opacity="0.08" />
  </svg>`;
}

function buildBentoVisualPlaceholderSvg(cardIdx, width, height, radius = 14) {
  const theme = GRID_BENTO_THEMES[cardIdx] || GRID_BENTO_THEMES[0];
  const { primary, border, visualGradStart, visualGradEnd } = theme;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <defs>
      <linearGradient id="vgrad-s-${cardIdx}" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${visualGradStart}" />
        <stop offset="100%" stop-color="${visualGradEnd}" />
      </linearGradient>
    </defs>
    <rect x="1" y="1" width="${width - 2}" height="${height - 2}" rx="${radius}" fill="url(#vgrad-s-${cardIdx})" stroke="${border}" stroke-width="1.2" />
    <line x1="${width * 0.33}" y1="8" x2="${width * 0.33}" y2="${height - 8}" stroke="${primary}" stroke-width="1" stroke-dasharray="3,3" opacity="0.18" />
    <line x1="${width * 0.66}" y1="8" x2="${width * 0.66}" y2="${height - 8}" stroke="${primary}" stroke-width="1" stroke-dasharray="3,3" opacity="0.18" />
    <line x1="8" y1="${height * 0.5}" x2="${width - 8}" y2="${height * 0.5}" stroke="${primary}" stroke-width="1" stroke-dasharray="3,3" opacity="0.18" />
    <g transform="translate(${width / 2 - 16}, ${height / 2 - 16})" opacity="0.45">
      <rect x="2" y="5" width="28" height="22" rx="4" fill="none" stroke="${primary}" stroke-width="2" />
      <circle cx="16" cy="16" r="6" fill="none" stroke="${primary}" stroke-width="2" />
      <path d="M 10 5 L 12 2 L 20 2 L 22 5 Z" fill="none" stroke="${primary}" stroke-width="2" />
    </g>
    <g transform="translate(${width / 2 - 40}, ${height - 28})">
      <rect width="80" height="18" rx="9" fill="#FFFFFF" opacity="0.85" />
      <text x="40" y="12.5" text-anchor="middle" fill="${primary}" font-size="8.5" font-weight="700" font-family="Inter, system-ui, sans-serif" letter-spacing="0.08em">VISUAL SLOT</text>
    </g>
  </svg>`;
}

function layoutGridBentoThree(elements = [], schema = {}, themeTokens = {}, canvas = {}) {
  const geom = GRID_BENTO_THREE_GEOM;
  const defaults = GRID_BENTO_THREE_DEFAULTS;

  const canvasW = canvas?.width || 1000;
  const canvasH = canvas?.height || 560;
  const scaleX = canvasW / geom.viewW;
  const scaleY = canvasH / geom.viewH;

  const contentMap = {};
  for (const el of elements) {
    const sid = el.slotId || el.slot_id;
    if (sid) {
      if (typeof el.content?.text === 'string' && el.content.text.trim()) {
        contentMap[sid] = el.content.text;
      } else if (typeof el.text === 'string' && el.text.trim()) {
        contentMap[sid] = el.text;
      }
    }
  }

  const getSlot = (id, fallback) => contentMap[id] || defaults[id] || fallback;

  const badgeText = getSlot('BADGE', defaults.BADGE);
  const headingText = getSlot('HEADING', defaults.HEADING);
  const subtitleText = getSlot('SUBTITLE', defaults.SUBTITLE);

  const card1Tag = getSlot('CARD_1_TAG', defaults.CARD_1_TAG);
  const card1Title = getSlot('CARD_1_TITLE', defaults.CARD_1_TITLE);
  const card1Body = getSlot('CARD_1_BODY', defaults.CARD_1_BODY);
  const card1Cta = getSlot('CARD_1_CTA', defaults.CARD_1_CTA);

  const card2Tag = getSlot('CARD_2_TAG', defaults.CARD_2_TAG);
  const card2Title = getSlot('CARD_2_TITLE', defaults.CARD_2_TITLE);
  const card2Body = getSlot('CARD_2_BODY', defaults.CARD_2_BODY);
  const card2Cta = getSlot('CARD_2_CTA', defaults.CARD_2_CTA);

  const card3Tag = getSlot('CARD_3_TAG', defaults.CARD_3_TAG);
  const card3Title = getSlot('CARD_3_TITLE', defaults.CARD_3_TITLE);
  const card3Body = getSlot('CARD_3_BODY', defaults.CARD_3_BODY);
  const card3Cta = getSlot('CARD_3_CTA', defaults.CARD_3_CTA);

  const finalElements = [];

  const pushElement = (el) => {
    const rx = el.placement?.x ?? el.rect?.x ?? el.x ?? 0;
    const ry = el.placement?.y ?? el.rect?.y ?? el.y ?? 0;
    const rw = el.placement?.width ?? el.rect?.width ?? el.width ?? 100;
    const rh = el.placement?.height ?? el.rect?.height ?? el.height ?? 50;
    const placement = {
      x: Math.round(rx),
      y: Math.round(ry),
      width: Math.max(1, Math.round(rw)),
      height: Math.max(1, Math.round(rh)),
      rotation: el.placement?.rotation ?? 0,
      opacity: el.placement?.opacity != null ? el.placement.opacity : 1,
    };
    const rect = {
      x: placement.x,
      y: placement.y,
      width: placement.width,
      height: placement.height,
    };
    const out = {
      ...el,
      x: placement.x,
      y: placement.y,
      width: placement.width,
      height: placement.height,
      placement,
      rect,
    };
    if (el.type === 'text') {
      out.content = {
        text: el.text || el.content?.text || '',
        fontSize: el.fontSize || el.content?.fontSize || el.style?.fontSize || 14,
        fontWeight: el.fontWeight || el.content?.fontWeight || el.style?.fontWeight || 400,
        color: el.color || el.content?.color || el.style?.color || '#0F172A',
        lineHeight: el.lineHeight || el.content?.lineHeight || el.style?.lineHeight || 1.4,
        letterSpacing: el.letterSpacing || el.content?.letterSpacing || el.style?.letterSpacing || 'normal',
        clipToSlot: false,
        ...(el.content || {}),
      };
    } else if (el.type === 'shape') {
      out.content = {
        svg: el.svgContent || el.content?.svg || '',
        colorMode: 'recolorable',
        ...(el.content || {}),
      };
    }
    finalElements.push(out);
  };

  // Header Elements
  pushElement({
    id: 'bento_header_badge',
    type: 'text',
    slotId: 'BADGE',
    layer: 10,
    text: badgeText,
    x: geom.badgeX * scaleX,
    y: geom.badgeY * scaleY,
    width: geom.badgeW * scaleX,
    height: geom.badgeH * scaleY,
    fontSize: 11,
    fontWeight: 700,
    color: '#0D9488',
    lineHeight: 1.2,
    letterSpacing: '0.08em',
    role: 'eyebrow',
  });

  pushElement({
    id: 'bento_header_heading',
    type: 'text',
    slotId: 'HEADING',
    layer: 10,
    text: headingText,
    x: geom.headingX * scaleX,
    y: geom.headingY * scaleY,
    width: geom.headingW * scaleX,
    height: geom.headingH * scaleY,
    fontSize: 28,
    fontWeight: 800,
    color: '#0F172A',
    lineHeight: 1.15,
    role: 'heading',
  });

  pushElement({
    id: 'bento_header_subtitle',
    type: 'text',
    slotId: 'SUBTITLE',
    layer: 10,
    text: subtitleText,
    x: geom.subtitleX * scaleX,
    y: geom.subtitleY * scaleY,
    width: geom.subtitleW * scaleX,
    height: geom.subtitleH * scaleY,
    fontSize: 14,
    fontWeight: 400,
    color: '#64748B',
    lineHeight: 1.4,
    role: 'subheading',
  });

  // Card 1 (Top Hero)
  pushElement({
    id: 'bento_card_1_bg',
    type: 'shape',
    role: 'card',
    slotId: 'CARD_1_BG',
    layer: 2,
    x: geom.card1.x * scaleX,
    y: geom.card1.y * scaleY,
    width: geom.card1.w * scaleX,
    height: geom.card1.h * scaleY,
    svgContent: buildBentoCardShapeSvg(0, geom.card1.w, geom.card1.h, geom.card1.radius),
  });

  pushElement({
    id: 'bento_card_1_tag',
    type: 'text',
    slotId: 'CARD_1_TAG',
    layer: 10,
    text: card1Tag,
    x: geom.card1.tagX * scaleX,
    y: geom.card1.tagY * scaleY,
    width: geom.card1.tagW * scaleX,
    height: geom.card1.tagH * scaleY,
    fontSize: 11,
    fontWeight: 800,
    color: GRID_BENTO_THEMES[0].primary,
    letterSpacing: '0.07em',
  });

  pushElement({
    id: 'bento_card_1_title',
    type: 'text',
    slotId: 'CARD_1_TITLE',
    layer: 10,
    text: card1Title,
    x: geom.card1.titleX * scaleX,
    y: geom.card1.titleY * scaleY,
    width: geom.card1.titleW * scaleX,
    height: geom.card1.titleH * scaleY,
    fontSize: 22,
    fontWeight: 800,
    color: '#0F172A',
    lineHeight: 1.2,
  });

  pushElement({
    id: 'bento_card_1_body',
    type: 'text',
    slotId: 'CARD_1_BODY',
    layer: 10,
    text: card1Body,
    x: geom.card1.bodyX * scaleX,
    y: geom.card1.bodyY * scaleY,
    width: geom.card1.bodyW * scaleX,
    height: geom.card1.bodyH * scaleY,
    fontSize: 13,
    fontWeight: 400,
    color: '#475569',
    lineHeight: 1.45,
  });

  pushElement({
    id: 'bento_card_1_cta',
    type: 'text',
    slotId: 'CARD_1_CTA',
    layer: 10,
    text: card1Cta,
    x: geom.card1.ctaX * scaleX,
    y: geom.card1.ctaY * scaleY,
    width: geom.card1.ctaW * scaleX,
    height: geom.card1.ctaH * scaleY,
    fontSize: 12,
    fontWeight: 700,
    color: GRID_BENTO_THEMES[0].primary,
  });

  pushElement({
    id: 'bento_card_1_visual',
    type: 'shape',
    role: 'visual',
    slotId: 'IMAGE_1',
    layer: 4,
    x: geom.card1.visualX * scaleX,
    y: geom.card1.visualY * scaleY,
    width: geom.card1.visualW * scaleX,
    height: geom.card1.visualH * scaleY,
    svgContent: buildBentoVisualPlaceholderSvg(0, geom.card1.visualW, geom.card1.visualH, geom.card1.visualRadius),
  });

  // Card 2 (Bottom Left)
  pushElement({
    id: 'bento_card_2_bg',
    type: 'shape',
    role: 'card',
    slotId: 'CARD_2_BG',
    layer: 2,
    x: geom.card2.x * scaleX,
    y: geom.card2.y * scaleY,
    width: geom.card2.w * scaleX,
    height: geom.card2.h * scaleY,
    svgContent: buildBentoCardShapeSvg(1, geom.card2.w, geom.card2.h, geom.card2.radius),
  });

  pushElement({
    id: 'bento_card_2_tag',
    type: 'text',
    slotId: 'CARD_2_TAG',
    layer: 10,
    text: card2Tag,
    x: geom.card2.tagX * scaleX,
    y: geom.card2.tagY * scaleY,
    width: geom.card2.tagW * scaleX,
    height: geom.card2.tagH * scaleY,
    fontSize: 10.5,
    fontWeight: 800,
    color: GRID_BENTO_THEMES[1].primary,
    letterSpacing: '0.07em',
  });

  pushElement({
    id: 'bento_card_2_title',
    type: 'text',
    slotId: 'CARD_2_TITLE',
    layer: 10,
    text: card2Title,
    x: geom.card2.titleX * scaleX,
    y: geom.card2.titleY * scaleY,
    width: geom.card2.titleW * scaleX,
    height: geom.card2.titleH * scaleY,
    fontSize: 18,
    fontWeight: 800,
    color: '#0F172A',
    lineHeight: 1.25,
  });

  pushElement({
    id: 'bento_card_2_body',
    type: 'text',
    slotId: 'CARD_2_BODY',
    layer: 10,
    text: card2Body,
    x: geom.card2.bodyX * scaleX,
    y: geom.card2.bodyY * scaleY,
    width: geom.card2.bodyW * scaleX,
    height: geom.card2.bodyH * scaleY,
    fontSize: 12,
    fontWeight: 400,
    color: '#475569',
    lineHeight: 1.4,
  });

  pushElement({
    id: 'bento_card_2_cta',
    type: 'text',
    slotId: 'CARD_2_CTA',
    layer: 10,
    text: card2Cta,
    x: geom.card2.ctaX * scaleX,
    y: geom.card2.ctaY * scaleY,
    width: geom.card2.ctaW * scaleX,
    height: geom.card2.ctaH * scaleY,
    fontSize: 12,
    fontWeight: 700,
    color: GRID_BENTO_THEMES[1].primary,
  });

  pushElement({
    id: 'bento_card_2_visual',
    type: 'shape',
    role: 'visual',
    slotId: 'IMAGE_2',
    layer: 4,
    x: geom.card2.visualX * scaleX,
    y: geom.card2.visualY * scaleY,
    width: geom.card2.visualW * scaleX,
    height: geom.card2.visualH * scaleY,
    svgContent: buildBentoVisualPlaceholderSvg(1, geom.card2.visualW, geom.card2.visualH, geom.card2.visualRadius),
  });

  // Card 3 (Bottom Right)
  pushElement({
    id: 'bento_card_3_bg',
    type: 'shape',
    role: 'card',
    slotId: 'CARD_3_BG',
    layer: 2,
    x: geom.card3.x * scaleX,
    y: geom.card3.y * scaleY,
    width: geom.card3.w * scaleX,
    height: geom.card3.h * scaleY,
    svgContent: buildBentoCardShapeSvg(2, geom.card3.w, geom.card3.h, geom.card3.radius),
  });

  pushElement({
    id: 'bento_card_3_tag',
    type: 'text',
    slotId: 'CARD_3_TAG',
    layer: 10,
    text: card3Tag,
    x: geom.card3.tagX * scaleX,
    y: geom.card3.tagY * scaleY,
    width: geom.card3.tagW * scaleX,
    height: geom.card3.tagH * scaleY,
    fontSize: 10.5,
    fontWeight: 800,
    color: GRID_BENTO_THEMES[2].primary,
    letterSpacing: '0.07em',
  });

  pushElement({
    id: 'bento_card_3_title',
    type: 'text',
    slotId: 'CARD_3_TITLE',
    layer: 10,
    text: card3Title,
    x: geom.card3.titleX * scaleX,
    y: geom.card3.titleY * scaleY,
    width: geom.card3.titleW * scaleX,
    height: geom.card3.titleH * scaleY,
    fontSize: 18,
    fontWeight: 800,
    color: '#0F172A',
    lineHeight: 1.25,
  });

  pushElement({
    id: 'bento_card_3_body',
    type: 'text',
    slotId: 'CARD_3_BODY',
    layer: 10,
    text: card3Body,
    x: geom.card3.bodyX * scaleX,
    y: geom.card3.bodyY * scaleY,
    width: geom.card3.bodyW * scaleX,
    height: geom.card3.bodyH * scaleY,
    fontSize: 12,
    fontWeight: 400,
    color: '#475569',
    lineHeight: 1.4,
  });

  pushElement({
    id: 'bento_card_3_cta',
    type: 'text',
    slotId: 'CARD_3_CTA',
    layer: 10,
    text: card3Cta,
    x: geom.card3.ctaX * scaleX,
    y: geom.card3.ctaY * scaleY,
    width: geom.card3.ctaW * scaleX,
    height: geom.card3.ctaH * scaleY,
    fontSize: 12,
    fontWeight: 700,
    color: GRID_BENTO_THEMES[2].primary,
  });

  pushElement({
    id: 'bento_card_3_visual',
    type: 'shape',
    role: 'visual',
    slotId: 'IMAGE_3',
    layer: 4,
    x: geom.card3.visualX * scaleX,
    y: geom.card3.visualY * scaleY,
    width: geom.card3.visualW * scaleX,
    height: geom.card3.visualH * scaleY,
    svgContent: buildBentoVisualPlaceholderSvg(2, geom.card3.visualW, geom.card3.visualH, geom.card3.visualRadius),
  });

  return finalElements;
}

module.exports = {
  GRID_BENTO_THREE_GEOM,
  GRID_BENTO_THEMES,
  GRID_BENTO_THREE_DEFAULTS,
  isGridBentoThreeLayout,
  buildBentoCardShapeSvg,
  buildBentoVisualPlaceholderSvg,
  layoutGridBentoThree,
};
