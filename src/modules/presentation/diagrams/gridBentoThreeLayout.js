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
    h: 196,
    radius: 18,
    imgX: 52,
    imgY: 124,
    imgW: 896,
    imgH: 180,
    imgRadius: 14,
  },

  // Card 2: Bottom Left Card (Half Width)
  card2: {
    x: 44,
    y: 326,
    w: 448,
    h: 214,
    radius: 18,
    imgX: 52,
    imgY: 334,
    imgW: 432,
    imgH: 198,
    imgRadius: 14,
  },

  // Card 3: Bottom Right Card (Half Width)
  card3: {
    x: 508,
    y: 326,
    w: 448,
    h: 214,
    radius: 18,
    imgX: 516,
    imgY: 334,
    imgW: 432,
    imgH: 198,
    imgRadius: 14,
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
};

function isGridBentoThreeLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase();
  return (
    id === 'grid_bento_three_v1' ||
    id === 'grid_bento_three' ||
    id === 'grid_three_asymmetric_v1'
  );
}

/**
 * Builds SVG card background with subtle gradient accents, delicate border, and soft drop shadow.
 */
function buildBentoCardShapeSvg(cardIdx, width, height, radius = 18) {
  const theme = GRID_BENTO_THEMES[cardIdx] || GRID_BENTO_THEMES[0];
  const { primary, tint, border } = theme;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <defs>
      <linearGradient id="bgrad-${cardIdx}" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#FFFFFF" />
        <stop offset="70%" stop-color="#FFFFFF" />
        <stop offset="100%" stop-color="${tint}" stop-opacity="0.8" />
      </linearGradient>
      <filter id="bshad-${cardIdx}" x="-4%" y="-6%" width="108%" height="116%" filterUnits="userSpaceOnUse">
        <feDropShadow dx="0" dy="4" stdDeviation="8" flood-color="#0F172A" flood-opacity="0.04" />
      </filter>
    </defs>
    <rect x="1.5" y="1.5" width="${width - 3}" height="${height - 3}" rx="${radius}" fill="url(#bgrad-${cardIdx})" stroke="${border}" stroke-width="1.5" filter="url(#bshad-${cardIdx})" />
    <path d="M 2 20 Q 2 2 20 2 L 60 2 Q 2 2 2 60 Z" fill="${primary}" opacity="0.08" />
  </svg>`;
}

/**
 * Builds the visual placeholder layout container (no photo baked in, sleek layout structure).
 */
function buildBentoVisualPlaceholderSvg(cardIdx, width, height, radius = 14) {
  const theme = GRID_BENTO_THEMES[cardIdx] || GRID_BENTO_THEMES[0];
  const { primary, border, visualGradStart, visualGradEnd } = theme;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <defs>
      <linearGradient id="vgrad-${cardIdx}" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${visualGradStart}" />
        <stop offset="100%" stop-color="${visualGradEnd}" />
      </linearGradient>
    </defs>
    <rect x="1" y="1" width="${width - 2}" height="${height - 2}" rx="${radius}" fill="url(#vgrad-${cardIdx})" stroke="${border}" stroke-width="1.2" />
    <line x1="${width * 0.33}" y1="8" x2="${width * 0.33}" y2="${height - 8}" stroke="${primary}" stroke-width="1" stroke-dasharray="3,3" opacity="0.18" />
    <line x1="${width * 0.66}" y1="8" x2="${width * 0.66}" y2="${height - 8}" stroke="${primary}" stroke-width="1" stroke-dasharray="3,3" opacity="0.18" />
    <line x1="8" y1="${height * 0.5}" x2="${width - 8}" y2="${height * 0.5}" stroke="${primary}" stroke-width="1" stroke-dasharray="3,3" opacity="0.18" />
    <g transform="translate(${width / 2 - 16}, ${height / 2 - 18})" opacity="0.45">
      <rect x="2" y="5" width="28" height="22" rx="4" fill="none" stroke="${primary}" stroke-width="2" />
      <circle cx="16" cy="16" r="6" fill="none" stroke="${primary}" stroke-width="2" />
      <path d="M 10 5 L 12 2 L 20 2 L 22 5 Z" fill="none" stroke="${primary}" stroke-width="2" />
    </g>
    <g transform="translate(${width / 2 - 42}, ${height - 28})">
      <rect width="84" height="18" rx="9" fill="#FFFFFF" opacity="0.85" />
      <text x="42" y="12.5" text-anchor="middle" fill="${primary}" font-size="8.5" font-weight="700" font-family="Inter, system-ui, sans-serif" letter-spacing="0.08em">VISUAL SLOT</text>
    </g>
  </svg>`;
}

/**
 * Layout compiler generating standard canvas elements for Grid Bento Three (Image-only containers).
 */
function layoutGridBentoThree(docOrElements = [], schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const geom = GRID_BENTO_THREE_GEOM;
  const defaults = GRID_BENTO_THREE_DEFAULTS;

  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1000;
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 560;
  const scaleX = canvasW / geom.viewW;
  const scaleY = canvasH / geom.viewH;

  const existingBySlot = {};
  const existingById = {};
  for (const el of elements) {
    const sid = el.slotId || el.slot_id;
    if (sid) existingBySlot[sid] = el;
    if (el.id) existingById[el.id] = el;
  }

  const getSlotText = (slotId, fallback) => {
    const el = existingBySlot[slotId] || existingById[slotId];
    if (typeof el?.content?.text === 'string' && el.content.text.trim()) {
      return el.content.text;
    }
    if (typeof el?.text === 'string' && el.text.trim()) {
      return el.text;
    }
    return defaults[slotId] || fallback;
  };

  const getImageContent = (idx) => {
    const slotId = `IMAGE_${idx}`;
    const el = existingBySlot[slotId] || existingById[slotId] || existingById[`bento_card_${idx}_img`];
    if (el?.content?.url || el?.content?.src) {
      return {
        url: el.content.url || el.content.src,
        name: el.content.name || slotId,
      };
    }
    return { url: null, name: slotId };
  };

  const badgeText = getSlotText('BADGE', defaults.BADGE);
  const headingText = getSlotText('HEADING', defaults.HEADING);
  const subtitleText = getSlotText('SUBTITLE', defaults.SUBTITLE);

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
        shape: 'rect',
        svg: el.svgContent || el.content?.svg || '',
        colorMode: 'recolorable',
        ...(el.content || {}),
      };
    } else if (el.type === 'image') {
      out.content = {
        url: el.content?.url || null,
        src: el.content?.src || null,
        fit: 'cover',
        borderRadius: el.content?.borderRadius || 14,
        placeholderSvg: el.content?.placeholderSvg || null,
        name: el.content?.name || el.slotId,
        ...(el.content || {}),
      };
    }
    finalElements.push(out);
  };

  // 1. Slide Header Elements
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

  // 2. Card 1 (Top Hero Card - Full Width Image Container)
  const img1Data = getImageContent(1);
  pushElement({
    id: 'bento_card_1_bg',
    type: 'shape',
    role: 'card',
    slotId: 'CARD_1_BG',
    layer: 1,
    x: geom.card1.x * scaleX,
    y: geom.card1.y * scaleY,
    width: geom.card1.w * scaleX,
    height: geom.card1.h * scaleY,
    svgContent: buildBentoCardShapeSvg(0, geom.card1.w, geom.card1.h, geom.card1.radius),
  });

  pushElement({
    id: 'bento_card_1_img',
    type: 'image',
    role: 'image',
    slotId: 'IMAGE_1',
    layer: 2,
    x: geom.card1.imgX * scaleX,
    y: geom.card1.imgY * scaleY,
    width: geom.card1.imgW * scaleX,
    height: geom.card1.imgH * scaleY,
    content: {
      url: img1Data.url || null,
      src: img1Data.url || null,
      fit: 'cover',
      borderRadius: geom.card1.imgRadius,
      name: img1Data.name || 'IMAGE_1',
      ...(img1Data.url ? {} : {
        placeholderSvg: buildBentoVisualPlaceholderSvg(
          0,
          geom.card1.imgW,
          geom.card1.imgH,
          geom.card1.imgRadius
        ),
      }),
    },
  });

  // 3. Card 2 (Bottom Left Card - Half Width Image Container)
  const img2Data = getImageContent(2);
  pushElement({
    id: 'bento_card_2_bg',
    type: 'shape',
    role: 'card',
    slotId: 'CARD_2_BG',
    layer: 1,
    x: geom.card2.x * scaleX,
    y: geom.card2.y * scaleY,
    width: geom.card2.w * scaleX,
    height: geom.card2.h * scaleY,
    svgContent: buildBentoCardShapeSvg(1, geom.card2.w, geom.card2.h, geom.card2.radius),
  });

  pushElement({
    id: 'bento_card_2_img',
    type: 'image',
    role: 'image',
    slotId: 'IMAGE_2',
    layer: 2,
    x: geom.card2.imgX * scaleX,
    y: geom.card2.imgY * scaleY,
    width: geom.card2.imgW * scaleX,
    height: geom.card2.imgH * scaleY,
    content: {
      url: img2Data.url || null,
      src: img2Data.url || null,
      fit: 'cover',
      borderRadius: geom.card2.imgRadius,
      name: img2Data.name || 'IMAGE_2',
      ...(img2Data.url ? {} : {
        placeholderSvg: buildBentoVisualPlaceholderSvg(
          1,
          geom.card2.imgW,
          geom.card2.imgH,
          geom.card2.imgRadius
        ),
      }),
    },
  });

  // 4. Card 3 (Bottom Right Card - Half Width Image Container)
  const img3Data = getImageContent(3);
  pushElement({
    id: 'bento_card_3_bg',
    type: 'shape',
    role: 'card',
    slotId: 'CARD_3_BG',
    layer: 1,
    x: geom.card3.x * scaleX,
    y: geom.card3.y * scaleY,
    width: geom.card3.w * scaleX,
    height: geom.card3.h * scaleY,
    svgContent: buildBentoCardShapeSvg(2, geom.card3.w, geom.card3.h, geom.card3.radius),
  });

  pushElement({
    id: 'bento_card_3_img',
    type: 'image',
    role: 'image',
    slotId: 'IMAGE_3',
    layer: 2,
    x: geom.card3.imgX * scaleX,
    y: geom.card3.imgY * scaleY,
    width: geom.card3.imgW * scaleX,
    height: geom.card3.imgH * scaleY,
    content: {
      url: img3Data.url || null,
      src: img3Data.url || null,
      fit: 'cover',
      borderRadius: geom.card3.imgRadius,
      name: img3Data.name || 'IMAGE_3',
      ...(img3Data.url ? {} : {
        placeholderSvg: buildBentoVisualPlaceholderSvg(
          2,
          geom.card3.imgW,
          geom.card3.imgH,
          geom.card3.imgRadius
        ),
      }),
    },
  });

  if (Array.isArray(docOrElements)) {
    return finalElements;
  }
  return { ...docOrElements, elements: finalElements };
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
