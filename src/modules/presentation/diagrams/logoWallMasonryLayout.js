/**
 * Athena VI — Logo Wall Masonry Layout Compiler (Backend)
 *
 * 8-Card Interlocking Masonry Showcase:
 *  - Ambient Corner Waves (top-left and bottom-right organic curved shapes)
 *  - Executive Centered Eyebrow Header: —— OUR TEAM ——
 *  - Centered Headline ("Trusted by leading teams") + Subtitle
 *  - 8-Card Masonry Grid (Mathematical Harmony with 12px uniform gaps):
 *    - Col 1: Card 1 (IMAGE_1, Top Landscape) + Card 2 (IMAGE_2, Bottom Tall Portrait)
 *    - Col 2: Card 3 (IMAGE_3, Top Tall Portrait)
 *    - Col 3: Card 4 (IMAGE_4, Top Landscape) + Card 5 (IMAGE_5, Mid Landscape)
 *    - Col 4: Card 6 (IMAGE_6, Top Tall Portrait)
 *    - Bottom Row: Card 7 (IMAGE_7, Spanning Wide Landscape) + Card 8 (IMAGE_8, Bottom Landscape)
 *  - Flush top at y = 144, flush mid-line at y = 396, flush bottom baseline at y = 538
 *  - Strict CommonJS and placement schema compliance for Joi canvasDocSchema validation
 */

const LOGO_WALL_MASONRY_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Ambient Corner Waves
  decorTopLeft: { x: 0, y: 0, w: 240, h: 180 },
  decorBottomRight: { x: 760, y: 380, w: 240, h: 180 },

  // Eyebrow Area: —— OUR TEAM ——
  eyebrowLineLeft: { x: 310, y: 26, w: 48, h: 2 },
  eyebrowText: { x: 368, y: 14, w: 264, h: 26 },
  eyebrowLineRight: { x: 642, y: 26, w: 48, h: 2 },

  // Slide Header Area
  headingX: 48,
  headingY: 44,
  headingW: 904,
  headingH: 48,

  subtitleX: 48,
  subtitleY: 94,
  subtitleW: 904,
  subtitleH: 34,

  // 8 Masonry Cards (12px uniform gaps, flush top at y: 144, flush baseline at y: 538)
  cardRadius: 14,
  card1: { x: 48, y: 144, w: 227, h: 130 },   // Col 1, Top Landscape
  card2: { x: 48, y: 286, w: 227, h: 252 },   // Col 1, Bottom Tall Portrait
  card3: { x: 287, y: 144, w: 179, h: 252 },  // Col 2, Top Tall Portrait
  card4: { x: 478, y: 144, w: 290, h: 120 },  // Col 3, Top Landscape
  card5: { x: 478, y: 276, w: 290, h: 120 },  // Col 3, Mid Landscape
  card6: { x: 780, y: 144, w: 172, h: 252 },  // Col 4, Top Tall Portrait
  card7: { x: 287, y: 408, w: 381, h: 130 },  // Bottom Row, Wide Landscape
  card8: { x: 680, y: 408, w: 272, h: 130 },  // Bottom Row, Right Landscape
};

const LOGO_WALL_MASONRY_DEFAULTS = {
  CATEGORY: 'OUR TEAM',
  HEADING: 'Trusted by leading teams',
  SUBTITLE: 'We work with innovative teams around the world to build better solutions, together.',
};

function isLogoWallMasonryLayout(layoutId) {
  const id = String(layoutId || '').toLowerCase().trim();
  return id === 'logo_wall_masonry_v1' || id === 'logo_wall_masonry';
}

/**
 * Builds the mountain-sun vector placeholder SVG badge
 */
function buildLogoWallPlaceholderSvg(cardIdx, width, height, radius = 14) {
  const iconW = Math.min(width * 0.45, 64);
  const iconH = iconW * 0.72;
  const iconX = (width - iconW) / 2;
  const iconY = (height - iconH) / 2;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <rect width="100%" height="100%" rx="${radius}" fill="#F0F4FD" stroke="#E2E8F0" stroke-width="1.2" />
    <g transform="translate(${iconX}, ${iconY})">
      <path d="M 0 ${iconH} L ${iconW * 0.38} ${iconH * 0.28} L ${iconW * 0.62} ${iconH * 0.62} L ${iconW * 0.78} ${iconH * 0.44} L ${iconW} ${iconH} Z" fill="#93C5FD" opacity="0.82" />
      <path d="M ${iconW * 0.22} ${iconH} L ${iconW * 0.48} ${iconH * 0.42} L ${iconW * 0.72} ${iconH * 0.74} L ${iconW * 0.88} ${iconH * 0.56} L ${iconW} ${iconH} Z" fill="#BFDBFE" opacity="0.65" />
      <circle cx="${iconW * 0.76}" cy="${iconH * 0.22}" r="${iconW * 0.1}" fill="#93C5FD" opacity="0.85" />
    </g>
  </svg>`;
}

/**
 * Compiles and positions all elements for Logo Wall Masonry (Backend)
 */
function layoutLogoWallMasonry(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1920;
  const canvasH = canvas.height || docOrElements?.canvas?.height || 1080;
  const geom = LOGO_WALL_MASONRY_GEOM;

  const scaleX = canvasW / geom.viewW;
  const scaleY = canvasH / geom.viewH;

  const schemaSlots = Array.isArray(schema?.slots) ? schema.slots : [];
  const schemaSlotMap = {};
  schemaSlots.forEach((s) => {
    if (s?.id) schemaSlotMap[s.id] = s;
  });

  const existingBySlot = {};
  const existingById = {};
  elements.forEach((el) => {
    if (el?.slotId) existingBySlot[el.slotId] = el;
    if (el?.id) existingById[el.id] = el;
  });

  const getSlotText = (slotId, fallback) => {
    const el = existingBySlot[slotId] || existingById[slotId];
    if (el?.content?.text && String(el.content.text).trim().length > 0) {
      return el.content.text;
    }
    const s = schemaSlotMap[slotId];
    if (s?.placeholder_text && String(s.placeholder_text).trim().length > 0) {
      return s.placeholder_text;
    }
    return fallback;
  };

  const getImageContent = (idx) => {
    const slotId = `IMAGE_${idx}`;
    const el = existingBySlot[slotId] || existingById[slotId] || existingById[`lwm_img_${idx}`];
    if (el?.content?.url || el?.content?.src) {
      return {
        url: el.content.url || el.content.src,
        name: el.content.name || slotId,
      };
    }
    return { url: null, name: slotId };
  };

  const categoryText = getSlotText('CATEGORY', LOGO_WALL_MASONRY_DEFAULTS.CATEGORY);
  const headingText = getSlotText('HEADING', LOGO_WALL_MASONRY_DEFAULTS.HEADING);
  const subtitleText = getSlotText('SUBTITLE', LOGO_WALL_MASONRY_DEFAULTS.SUBTITLE);

  const outElements = [];

  const pushElement = (config) => {
    const x = Math.round(config.x);
    const y = Math.round(config.y);
    const width = Math.max(1, Math.round(config.width));
    const height = Math.max(1, Math.round(config.height));

    const basePlacement = {
      x,
      y,
      width,
      height,
      rotation: 0,
      opacity: config.opacity !== undefined ? config.opacity : 1,
    };

    if (config.type === 'text') {
      outElements.push({
        id: config.id,
        type: 'text',
        slotId: config.slotId,
        role: config.role || 'text',
        layer: config.layer || 10,
        placement: basePlacement,
        rect: { ...basePlacement },
        content: {
          text: config.text,
          fontSize: Math.round(config.fontSize * Math.min(scaleX, scaleY)),
          fontWeight: config.fontWeight || 600,
          color: config.color || '#0F172A',
          align: config.align || 'center',
          lineHeight: config.lineHeight || 1.25,
          letterSpacing: config.letterSpacing || 'normal',
          whiteSpace: config.whiteSpace || 'normal',
          clipToSlot: false,
        },
      });
    } else if (config.type === 'image') {
      const imgData = config.imgData || {};
      outElements.push({
        id: config.id,
        type: 'image',
        slotId: config.slotId,
        role: 'image',
        layer: config.layer || 2,
        placement: basePlacement,
        rect: { ...basePlacement },
        content: {
          url: imgData.url || null,
          src: imgData.url || null,
          fit: 'contain',
          borderRadius: config.borderRadius || 14,
          name: imgData.name || config.slotId,
          ...(imgData.url ? {} : {
            placeholderSvg: buildLogoWallPlaceholderSvg(config.cardIdx, width, height, config.borderRadius || 14),
          }),
        },
      });
    } else if (config.type === 'shape') {
      outElements.push({
        id: config.id,
        type: 'shape',
        slotId: config.slotId,
        role: config.role || 'decoration',
        layer: config.layer || 1,
        placement: basePlacement,
        rect: { ...basePlacement },
        content: {
          shape: 'rect',
          fill: config.fill || '#F0F4FD',
          stroke: config.stroke || '#E2E8F0',
          strokeWidth: config.strokeWidth || 1.2,
          borderRadius: config.borderRadius || 14,
          svgContent: config.svgContent || null,
        },
      });
    }
  };

  // 0. Ambient Corner Waves (layer: 0)
  pushElement({
    id: 'lwm_decor_tl',
    type: 'shape',
    slotId: 'DECOR_TL',
    role: 'decoration',
    layer: 0,
    x: geom.decorTopLeft.x * scaleX,
    y: geom.decorTopLeft.y * scaleY,
    width: geom.decorTopLeft.w * scaleX,
    height: geom.decorTopLeft.h * scaleY,
    svgContent: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 180" width="100%" height="100%"><path d="M 0 0 L 180 0 C 130 50, 60 120, 0 160 Z" fill="#EEF2FF" opacity="0.85" /><path d="M 0 0 L 120 0 C 90 35, 45 80, 0 110 Z" fill="#E0E7FF" opacity="0.6" /></svg>`,
  });
  pushElement({
    id: 'lwm_decor_br',
    type: 'shape',
    slotId: 'DECOR_BR',
    role: 'decoration',
    layer: 0,
    x: geom.decorBottomRight.x * scaleX,
    y: geom.decorBottomRight.y * scaleY,
    width: geom.decorBottomRight.w * scaleX,
    height: geom.decorBottomRight.h * scaleY,
    svgContent: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 180" width="100%" height="100%"><path d="M 240 180 L 60 180 C 110 130, 180 60, 240 20 Z" fill="#EEF2FF" opacity="0.85" /><path d="M 240 180 L 120 180 C 150 145, 195 100, 240 70 Z" fill="#E0E7FF" opacity="0.6" /></svg>`,
  });

  // 1. Eyebrow Header: —— OUR TEAM —— (layer: 10)
  pushElement({
    id: 'lwm_eyebrow_line_l',
    type: 'shape',
    slotId: 'EYEBROW_LINE_L',
    role: 'decoration',
    layer: 10,
    fill: '#6366F1',
    stroke: '#6366F1',
    borderRadius: 1,
    x: geom.eyebrowLineLeft.x * scaleX,
    y: geom.eyebrowLineLeft.y * scaleY,
    width: geom.eyebrowLineLeft.w * scaleX,
    height: geom.eyebrowLineLeft.h * scaleY,
  });

  pushElement({
    id: 'lwm_eyebrow_text',
    type: 'text',
    slotId: 'CATEGORY',
    role: 'eyebrow',
    layer: 10,
    text: categoryText,
    x: geom.eyebrowText.x * scaleX,
    y: geom.eyebrowText.y * scaleY,
    width: geom.eyebrowText.w * scaleX,
    height: geom.eyebrowText.h * scaleY,
    fontSize: 9,
    fontWeight: 700,
    color: '#4F46E5',
    align: 'center',
    letterSpacing: '0.18em',
    whiteSpace: 'nowrap',
  });

  pushElement({
    id: 'lwm_eyebrow_line_r',
    type: 'shape',
    slotId: 'EYEBROW_LINE_R',
    role: 'decoration',
    layer: 10,
    fill: '#6366F1',
    stroke: '#6366F1',
    borderRadius: 1,
    x: geom.eyebrowLineRight.x * scaleX,
    y: geom.eyebrowLineRight.y * scaleY,
    width: geom.eyebrowLineRight.w * scaleX,
    height: geom.eyebrowLineRight.h * scaleY,
  });

  // 2. Centered Heading
  pushElement({
    id: 'lwm_heading',
    type: 'text',
    slotId: 'HEADING',
    role: 'heading',
    layer: 10,
    text: headingText,
    x: geom.headingX * scaleX,
    y: geom.headingY * scaleY,
    width: geom.headingW * scaleX,
    height: geom.headingH * scaleY,
    fontSize: 22,
    fontWeight: 800,
    color: '#0B192C',
    align: 'center',
    lineHeight: 1.18,
    whiteSpace: 'nowrap',
  });

  // 3. Centered Subtitle
  pushElement({
    id: 'lwm_subtitle',
    type: 'text',
    slotId: 'SUBTITLE',
    role: 'subheading',
    layer: 10,
    text: subtitleText,
    x: geom.subtitleX * scaleX,
    y: geom.subtitleY * scaleY,
    width: geom.subtitleW * scaleX,
    height: geom.subtitleH * scaleY,
    fontSize: 10.5,
    fontWeight: 400,
    color: '#64748B',
    align: 'center',
    lineHeight: 1.35,
  });

  // 4. 8 Masonry Logo Cards
  const cards = [
    { slotId: 'IMAGE_1', cardIdx: 0, geom: geom.card1 },
    { slotId: 'IMAGE_2', cardIdx: 1, geom: geom.card2 },
    { slotId: 'IMAGE_3', cardIdx: 2, geom: geom.card3 },
    { slotId: 'IMAGE_4', cardIdx: 3, geom: geom.card4 },
    { slotId: 'IMAGE_5', cardIdx: 4, geom: geom.card5 },
    { slotId: 'IMAGE_6', cardIdx: 5, geom: geom.card6 },
    { slotId: 'IMAGE_7', cardIdx: 6, geom: geom.card7 },
    { slotId: 'IMAGE_8', cardIdx: 7, geom: geom.card8 },
  ];

  cards.forEach((card, idx) => {
    const imgData = getImageContent(idx + 1);
    // Background tile
    pushElement({
      id: `lwm_card_bg_${idx + 1}`,
      type: 'shape',
      slotId: `CARD_BG_${idx + 1}`,
      role: 'decoration',
      layer: 1,
      fill: '#F0F4FD',
      stroke: '#E2E8F0',
      strokeWidth: 1.2,
      borderRadius: geom.cardRadius,
      x: card.geom.x * scaleX,
      y: card.geom.y * scaleY,
      width: card.geom.w * scaleX,
      height: card.geom.h * scaleY,
    });
    // Logo / image element
    pushElement({
      id: `lwm_img_${idx + 1}`,
      type: 'image',
      slotId: card.slotId,
      cardIdx: card.cardIdx,
      layer: 2,
      imgData,
      borderRadius: geom.cardRadius,
      x: (card.geom.x + 16) * scaleX,
      y: (card.geom.y + 12) * scaleY,
      width: (card.geom.w - 32) * scaleX,
      height: (card.geom.h - 24) * scaleY,
    });
  });

  if (Array.isArray(docOrElements)) {
    return outElements;
  }
  return { ...docOrElements, elements: outElements };
}

module.exports = {
  LOGO_WALL_MASONRY_GEOM,
  LOGO_WALL_MASONRY_DEFAULTS,
  isLogoWallMasonryLayout,
  buildLogoWallPlaceholderSvg,
  layoutLogoWallMasonry,
};
