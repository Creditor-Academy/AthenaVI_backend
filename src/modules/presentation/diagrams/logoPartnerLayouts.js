/**
 * Logo Partner Layouts Engine (Backend Server-Side Compiler)
 * Layout IDs:
 *  - logo_partner_grid_v1 / logo_partner_grid
 *  - logo_partner_strip_v1 / logo_partner_strip
 *
 * Executive Partner Showcase:
 *  - Grid: Balanced 6-card grid (3 cols x 2 rows) with distinct card tile backgrounds
 *  - Strip: Unified horizontal banner containing 4 well-proportioned logo cards + trust caption
 *  - Full placement schema compliance ({ x, y, width, height, rotation: 0, opacity: 1 })
 *  - Text clipToSlot: false to eliminate ascender/descender clipping
 *  - Preserves user uploaded logos with fit: 'contain'
 */

const LOGO_PARTNER_GRID_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Ambient Corner Waves
  decorTopLeft: { x: 0, y: 0, w: 240, h: 180 },
  decorBottomRight: { x: 760, y: 380, w: 240, h: 180 },

  // Eyebrow Area: —— OUR PARTNERS ——
  eyebrowLineLeft: { x: 310, y: 28, w: 48, h: 2 },
  eyebrowText: { x: 368, y: 16, w: 264, h: 26 },
  eyebrowLineRight: { x: 642, y: 28, w: 48, h: 2 },

  // Slide Header Area (Heading only)
  headingX: 56,
  headingY: 48,
  headingW: 888,
  headingH: 52,

  // 6 Logo Cards across 3 cols x 2 rows
  cardW: 272,
  cardH: 176,
  cardRadius: 16,

  // Row 1
  card1: { x: 56, y: 136, w: 272, h: 176, radius: 16 },
  card2: { x: 364, y: 136, w: 272, h: 176, radius: 16 },
  card3: { x: 672, y: 136, w: 272, h: 176, radius: 16 },

  // Row 2
  card4: { x: 56, y: 334, w: 272, h: 176, radius: 16 },
  card5: { x: 364, y: 334, w: 272, h: 176, radius: 16 },
  card6: { x: 672, y: 334, w: 272, h: 176, radius: 16 },
};

const LOGO_PARTNER_STRIP_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Slide Header Area (Heading only)
  headingX: 48,
  headingY: 46,
  headingW: 904,
  headingH: 54,

  // Banner Container
  banner: {
    x: 48,
    y: 146,
    w: 904,
    h: 228,
    radius: 18,
  },

  // 4 Logo Cards inside banner
  card1: { x: 72, y: 174, w: 196, h: 172, radius: 12 },
  card2: { x: 292, y: 174, w: 196, h: 172, radius: 12 },
  card3: { x: 512, y: 174, w: 196, h: 172, radius: 12 },
  card4: { x: 732, y: 174, w: 196, h: 172, radius: 12 },

  // Trust / Social Proof Caption
  trustX: 48,
  trustY: 416,
  trustW: 904,
  trustH: 34,
};

const LOGO_PARTNER_THEMES = [
  { primary: '#4F46E5', tint: '#EEF2FF', border: '#C7D2FE', bg: '#F8FAFF' },
  { primary: '#0D9488', tint: '#F0FDFA', border: '#CCFBF1', bg: '#F8FAFF' },
  { primary: '#0284C7', tint: '#F0F9FF', border: '#BAE6FD', bg: '#F8FAFF' },
  { primary: '#D97706', tint: '#FFFBEB', border: '#FDE68A', bg: '#F8FAFF' },
  { primary: '#7C3AED', tint: '#F5F3FF', border: '#DDD6FE', bg: '#F8FAFF' },
  { primary: '#E11D48', tint: '#FFF1F2', border: '#FECDD3', bg: '#F8FAFF' },
];

const LOGO_PARTNER_DEFAULTS = {
  GRID_CATEGORY: 'OUR PARTNERS',
  GRID_HEADING: 'Trusted by Industry Leaders',
  GRID_SUBTITLE: 'Collaborating with visionary teams to deliver world-class solutions.',
  STRIP_HEADING: 'Partners',
  STRIP_SUBTITLE: 'Powering high-growth companies and enterprise teams worldwide.',
  TRUST_LABEL: 'Over 10,000+ organizations build and scale with our ecosystem',
};

function isLogoPartnerGridLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase();
  return id === 'logo_partner_grid_v1' || id === 'logo_partner_grid';
}

function isLogoPartnerStripLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase();
  return id === 'logo_partner_strip_v1' || id === 'logo_partner_strip';
}

/**
 * Builds vector mountain-sun SVG placeholder for partner logo slots
 */
function buildLogoPlaceholderSvg(cardIdx, width, height, radius = 16) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <rect x="1" y="1" width="${width - 2}" height="${height - 2}" rx="${radius}" fill="#F8FAFF" stroke="#E2E8F0" stroke-width="1.2" />
    <g transform="translate(${Math.round(width / 2 - 28)}, ${Math.round(height / 2 - 24)})" opacity="0.65">
      <rect x="0" y="0" width="56" height="48" rx="10" fill="#EEF2FF" stroke="#C7D2FE" stroke-width="1.2" />
      <circle cx="38" cy="16" r="4.5" fill="#818CF8" />
      <path d="M 10 38 L 22 24 L 32 34 L 38 28 L 48 38 Z" fill="#818CF8" stroke="#818CF8" stroke-width="1" stroke-linejoin="round" />
    </g>
  </svg>`;
}

/**
 * Compiler for Logo Partner Grid (6 balanced cards in 3x2 grid)
 */
function layoutLogoPartnerGrid(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1920;
  const canvasH = canvas.height || docOrElements?.canvas?.height || 1080;
  const geom = LOGO_PARTNER_GRID_GEOM;

  const scaleX = canvasW / geom.viewW;
  const scaleY = canvasH / geom.viewH;

  const findText = (matcher, fallback) => {
    const el = elements.find((e) => {
      const sid = String(e.slotId || '').toUpperCase();
      const role = String(e.role || '').toUpperCase();
      return matcher(sid, role);
    });
    const txt = el?.content?.text || el?.text || el?.content?.heading || el?.content?.title;
    return txt && String(txt).trim().length > 0 ? String(txt).trim() : fallback;
  };

  const categoryText = findText(
    (s, r) => s === 'CATEGORY' || s === 'EYEBROW' || r === 'EYEBROW',
    LOGO_PARTNER_DEFAULTS.GRID_CATEGORY
  );

  const headingText = findText(
    (s, r) => s === 'HEADING' || s.includes('TITLE') || r === 'HEADING',
    LOGO_PARTNER_DEFAULTS.GRID_HEADING
  );

  const subtitleText = findText(
    (s, r) => s === 'SUBTITLE' || s.includes('SUB') || s.includes('BODY') || r === 'SUBHEADING',
    LOGO_PARTNER_DEFAULTS.GRID_SUBTITLE
  );

  const existingImages = elements.filter(
    (e) => e.type === 'image' || /^IMAGE_\d+$/i.test(String(e.slotId || ''))
  );

  const getImageContent = (slotNum) => {
    const el =
      elements.find((e) => String(e.slotId || '').toUpperCase() === `IMAGE_${slotNum}`) ||
      existingImages[slotNum - 1];

    const url = el?.content?.url || el?.content?.src || el?.url || el?.src || null;
    return {
      url,
      fit: 'contain',
      borderRadius: 16,
      name: el?.content?.name || `Partner ${slotNum}`,
    };
  };

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
          borderRadius: 16,
          name: imgData.name || config.slotId,
          ...(imgData.url ? {} : {
            placeholderSvg: buildLogoPlaceholderSvg(config.cardIdx, width, height, 16),
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
          fill: config.fill || '#F8FAFF',
          stroke: config.stroke || '#E2E8F0',
          strokeWidth: config.strokeWidth || 1.2,
          borderRadius: config.borderRadius || 16,
          svgContent: config.svgContent || null,
        },
      });
    }
  };

  // 0. Ambient Corner Waves (layer: 0)
  pushElement({
    id: 'lpg_decor_tl',
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
    id: 'lpg_decor_br',
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

  // 1. Eyebrow Header: —— OUR PARTNERS —— (layer: 10)
  pushElement({
    id: 'lpg_eyebrow_line_l',
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
    id: 'lpg_eyebrow_text',
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
    id: 'lpg_eyebrow_line_r',
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

  // 2. 6 Logo Cards (3x2 grid)
  const cards = [
    { slotId: 'IMAGE_1', cardIdx: 0, geom: geom.card1 },
    { slotId: 'IMAGE_2', cardIdx: 1, geom: geom.card2 },
    { slotId: 'IMAGE_3', cardIdx: 2, geom: geom.card3 },
    { slotId: 'IMAGE_4', cardIdx: 3, geom: geom.card4 },
    { slotId: 'IMAGE_5', cardIdx: 4, geom: geom.card5 },
    { slotId: 'IMAGE_6', cardIdx: 5, geom: geom.card6 },
  ];

  cards.forEach((card, idx) => {
    const imgData = getImageContent(idx + 1);
    // Card background tile
    pushElement({
      id: `lpg_card_bg_${idx + 1}`,
      type: 'shape',
      slotId: `CARD_BG_${idx + 1}`,
      role: 'decoration',
      layer: 1,
      fill: '#F8FAFF',
      stroke: '#E2E8F0',
      strokeWidth: 1.2,
      borderRadius: 16,
      x: card.geom.x * scaleX,
      y: card.geom.y * scaleY,
      width: card.geom.w * scaleX,
      height: card.geom.h * scaleY,
    });
    // Logo image
    pushElement({
      id: `lpg_img_${idx + 1}`,
      type: 'image',
      slotId: card.slotId,
      cardIdx: card.cardIdx,
      layer: 2,
      imgData,
      x: (card.geom.x + 20) * scaleX,
      y: (card.geom.y + 16) * scaleY,
      width: (card.geom.w - 40) * scaleX,
      height: (card.geom.h - 32) * scaleY,
    });
  });

  // 3. Centered Heading
  pushElement({
    id: 'lpg_heading',
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

  if (Array.isArray(docOrElements)) {
    return outElements;
  }
  return { ...docOrElements, elements: outElements };
}

/**
 * Compiler for Logo Partner Strip (Unified banner with 4 balanced logo cards + trust label)
 */
function layoutLogoPartnerStrip(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1920;
  const canvasH = canvas.height || docOrElements?.canvas?.height || 1080;
  const geom = LOGO_PARTNER_STRIP_GEOM;

  const scaleX = canvasW / geom.viewW;
  const scaleY = canvasH / geom.viewH;

  const findText = (matcher, fallback) => {
    const el = elements.find((e) => {
      const sid = String(e.slotId || '').toUpperCase();
      const role = String(e.role || '').toUpperCase();
      return matcher(sid, role);
    });
    const txt = el?.content?.text || el?.text || el?.content?.heading || el?.content?.title;
    return txt && String(txt).trim().length > 0 ? String(txt).trim() : fallback;
  };

  const headingText = findText(
    (s, r) => s === 'HEADING' || s.includes('TITLE') || r === 'HEADING',
    LOGO_PARTNER_DEFAULTS.STRIP_HEADING
  );

  const subtitleText = findText(
    (s, r) => s === 'SUBTITLE' || s.includes('SUB') || s.includes('BODY') || r === 'SUBHEADING',
    LOGO_PARTNER_DEFAULTS.STRIP_SUBTITLE
  );

  const trustText = findText(
    (s) => s === 'TRUST_LABEL' || s.includes('TRUST') || s.includes('CAPTION'),
    LOGO_PARTNER_DEFAULTS.TRUST_LABEL
  );

  const existingImages = elements.filter(
    (e) => e.type === 'image' || /^IMAGE_\d+$/i.test(String(e.slotId || ''))
  );

  const getImageContent = (slotNum) => {
    const el =
      elements.find((e) => String(e.slotId || '').toUpperCase() === `IMAGE_${slotNum}`) ||
      existingImages[slotNum - 1];

    const url = el?.content?.url || el?.content?.src || el?.url || el?.src || null;
    return {
      url,
      fit: 'contain',
      borderRadius: 12,
      name: el?.content?.name || `Partner ${slotNum}`,
    };
  };

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
          borderRadius: 12,
          name: imgData.name || config.slotId,
          ...(imgData.url ? {} : {
            placeholderSvg: buildLogoPlaceholderSvg(config.cardIdx, width, height, 12),
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
          fill: config.fill || '#F8FAFC',
          stroke: config.stroke || '#E2E8F0',
          strokeWidth: config.strokeWidth || 1.2,
          borderRadius: config.borderRadius || 18,
          svgContent: config.svgContent || null,
        },
      });
    }
  };

  // 1. Unified Frosted Banner Container (layer: 1)
  pushElement({
    id: 'lps_banner_bg',
    type: 'shape',
    slotId: 'BANNER_BG',
    role: 'decoration',
    layer: 1,
    fill: '#F8FAFC',
    stroke: '#E2E8F0',
    strokeWidth: 1.2,
    borderRadius: 18,
    x: geom.banner.x * scaleX,
    y: geom.banner.y * scaleY,
    width: geom.banner.w * scaleX,
    height: geom.banner.h * scaleY,
  });

  // 2. 4 Logo Cards inside banner (layer: 2)
  const cards = [
    { slotId: 'IMAGE_1', cardIdx: 0, geom: geom.card1 },
    { slotId: 'IMAGE_2', cardIdx: 1, geom: geom.card2 },
    { slotId: 'IMAGE_3', cardIdx: 2, geom: geom.card3 },
    { slotId: 'IMAGE_4', cardIdx: 3, geom: geom.card4 },
  ];

  cards.forEach((card, idx) => {
    const imgData = getImageContent(idx + 1);
    // Individual inner card tile
    pushElement({
      id: `lps_tile_bg_${idx + 1}`,
      type: 'shape',
      slotId: `TILE_BG_${idx + 1}`,
      role: 'decoration',
      layer: 2,
      fill: '#FFFFFF',
      stroke: '#E2E8F0',
      strokeWidth: 1,
      borderRadius: 12,
      x: card.geom.x * scaleX,
      y: card.geom.y * scaleY,
      width: card.geom.w * scaleX,
      height: card.geom.h * scaleY,
    });
    // Logo image
    pushElement({
      id: `lps_img_${idx + 1}`,
      type: 'image',
      slotId: card.slotId,
      cardIdx: card.cardIdx,
      layer: 3,
      imgData,
      x: (card.geom.x + 16) * scaleX,
      y: (card.geom.y + 14) * scaleY,
      width: (card.geom.w - 32) * scaleX,
      height: (card.geom.h - 28) * scaleY,
    });
  });

  // 3. Centered Heading
  pushElement({
    id: 'lps_heading',
    type: 'text',
    slotId: 'HEADING',
    role: 'heading',
    layer: 10,
    text: headingText,
    x: geom.headingX * scaleX,
    y: geom.headingY * scaleY,
    width: geom.headingW * scaleX,
    height: geom.headingH * scaleY,
    fontSize: 27,
    fontWeight: 800,
    color: '#0F172A',
    align: 'center',
    lineHeight: 1.2,
  });

  // 4. Trust / Social Proof Caption
  pushElement({
    id: 'lps_trust',
    type: 'text',
    slotId: 'TRUST_LABEL',
    role: 'caption',
    layer: 10,
    text: trustText,
    x: geom.trustX * scaleX,
    y: geom.trustY * scaleY,
    width: geom.trustW * scaleX,
    height: geom.trustH * scaleY,
    fontSize: 12,
    fontWeight: 500,
    color: '#64748B',
    align: 'center',
    lineHeight: 1.3,
  });

  if (Array.isArray(docOrElements)) {
    return outElements;
  }
  return { ...docOrElements, elements: outElements };
}

// ============================================================================
// 3. LOGO WALL (logo_wall_v1)
// ============================================================================

const LOGO_WALL_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Ambient Corner Waves
  decorTopLeft: { x: 0, y: 0, w: 240, h: 180 },
  decorBottomRight: { x: 760, y: 380, w: 240, h: 180 },

  // Eyebrow Area: —— OUR PARTNERS ——
  eyebrowLineLeft: { x: 310, y: 28, w: 48, h: 2 },
  eyebrowText: { x: 368, y: 16, w: 264, h: 26 },
  eyebrowLineRight: { x: 642, y: 28, w: 48, h: 2 },

  // Slide Header Area (Heading only)
  headingX: 56,
  headingY: 48,
  headingW: 888,
  headingH: 52,

  // 8 Logo Cards across 4 cols x 2 rows (card: 214 x 176, radius 16)
  cardW: 214,
  cardH: 176,
  cardRadius: 16,

  // Row 1
  card1: { x: 48, y: 136, w: 214, h: 176, radius: 16 },
  card2: { x: 278, y: 136, w: 214, h: 176, radius: 16 },
  card3: { x: 508, y: 136, w: 214, h: 176, radius: 16 },
  card4: { x: 738, y: 136, w: 214, h: 176, radius: 16 },

  // Row 2 (8 cards mode)
  card5: { x: 48, y: 328, w: 214, h: 176, radius: 16 },
  card6: { x: 278, y: 328, w: 214, h: 176, radius: 16 },
  card7: { x: 508, y: 328, w: 214, h: 176, radius: 16 },
  card8: { x: 738, y: 328, w: 214, h: 176, radius: 16 },

  // Row 2 centered (if only 7 cards)
  card5_stagger: { x: 163, y: 328, w: 214, h: 176, radius: 16 },
  card6_stagger: { x: 393, y: 328, w: 214, h: 176, radius: 16 },
  card7_stagger: { x: 623, y: 328, w: 214, h: 176, radius: 16 },
};

const LOGO_WALL_DEFAULTS = {
  CATEGORY: 'OUR PARTNERS',
  HEADING: 'Trusted by leading teams',
};

function isLogoWallLayout(layoutId) {
  const id = String(layoutId || '').toLowerCase().trim();
  return id === 'logo_wall_v1' || id === 'logo_wall';
}

/**
 * Compiles and positions all elements for Logo Wall (8 logo cards across 4x2 grid)
 */
function layoutLogoWall(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1920;
  const canvasH = canvas.height || docOrElements?.canvas?.height || 1080;
  const geom = LOGO_WALL_GEOM;

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
    const el = existingBySlot[slotId] || existingById[slotId] || existingById[`lw_img_${idx}`];
    if (el?.content?.url || el?.content?.src) {
      return {
        url: el.content.url || el.content.src,
        name: el.content.name || slotId,
      };
    }
    return { url: null, name: slotId };
  };

  const categoryText = getSlotText('CATEGORY', LOGO_WALL_DEFAULTS.CATEGORY);
  const headingText = getSlotText('HEADING', LOGO_WALL_DEFAULTS.HEADING);

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
          borderRadius: 16,
          name: imgData.name || config.slotId,
          ...(imgData.url ? {} : {
            placeholderSvg: buildLogoPlaceholderSvg(config.cardIdx, width, height, 16),
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
          fill: config.fill || '#F8FAFF',
          stroke: config.stroke || '#E2E8F0',
          strokeWidth: config.strokeWidth || 1.2,
          borderRadius: 16,
          svgContent: config.svgContent || null,
        },
      });
    }
  };

  // 0. Ambient Corner Waves (layer: 0)
  pushElement({
    id: 'lw_decor_tl',
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
    id: 'lw_decor_br',
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

  // 1. Eyebrow Header: —— OUR PARTNERS —— (layer: 10)
  pushElement({
    id: 'lw_eyebrow_line_l',
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
    id: 'lw_eyebrow_text',
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
    id: 'lw_eyebrow_line_r',
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

  // 2. 8 Logo Cards (4x2 grid)
  const hasEight = Boolean(
    schemaSlotMap['IMAGE_8'] ||
    existingBySlot['IMAGE_8'] ||
    getImageContent(8).url
  );

  const cards = [
    { slotId: 'IMAGE_1', cardIdx: 0, geom: geom.card1 },
    { slotId: 'IMAGE_2', cardIdx: 1, geom: geom.card2 },
    { slotId: 'IMAGE_3', cardIdx: 2, geom: geom.card3 },
    { slotId: 'IMAGE_4', cardIdx: 3, geom: geom.card4 },
    { slotId: 'IMAGE_5', cardIdx: 4, geom: hasEight ? geom.card5 : geom.card5_stagger },
    { slotId: 'IMAGE_6', cardIdx: 5, geom: hasEight ? geom.card6 : geom.card6_stagger },
    { slotId: 'IMAGE_7', cardIdx: 6, geom: hasEight ? geom.card7 : geom.card7_stagger },
    ...(hasEight ? [{ slotId: 'IMAGE_8', cardIdx: 7, geom: geom.card8 }] : []),
  ];

  cards.forEach((card, idx) => {
    const imgData = getImageContent(idx + 1);
    // Card background tile
    pushElement({
      id: `lw_card_bg_${idx + 1}`,
      type: 'shape',
      slotId: `CARD_BG_${idx + 1}`,
      role: 'decoration',
      layer: 1,
      fill: '#F8FAFF',
      stroke: '#E2E8F0',
      strokeWidth: 1.2,
      borderRadius: 16,
      x: card.geom.x * scaleX,
      y: card.geom.y * scaleY,
      width: card.geom.w * scaleX,
      height: card.geom.h * scaleY,
    });
    // Logo image
    pushElement({
      id: `lw_img_${idx + 1}`,
      type: 'image',
      slotId: card.slotId,
      cardIdx: card.cardIdx,
      layer: 2,
      imgData,
      x: (card.geom.x + 16) * scaleX,
      y: (card.geom.y + 14) * scaleY,
      width: (card.geom.w - 32) * scaleX,
      height: (card.geom.h - 28) * scaleY,
    });
  });

  // 3. Centered Heading
  pushElement({
    id: 'lw_heading',
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

  if (Array.isArray(docOrElements)) {
    return outElements;
  }
  return { ...docOrElements, elements: outElements };
}

module.exports = {
  LOGO_PARTNER_GRID_GEOM,
  LOGO_PARTNER_STRIP_GEOM,
  LOGO_WALL_GEOM,
  LOGO_PARTNER_THEMES,
  LOGO_PARTNER_DEFAULTS,
  LOGO_WALL_DEFAULTS,
  isLogoPartnerGridLayout,
  isLogoPartnerStripLayout,
  isLogoWallLayout,
  buildLogoPlaceholderSvg,
  layoutLogoPartnerGrid,
  layoutLogoPartnerStrip,
  layoutLogoWall,
};

