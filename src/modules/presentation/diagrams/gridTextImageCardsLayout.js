/**
 * Grid Text Image Cards Layout Engine (Backend Server-Side Compiler)
 * Layout IDs:
 *  - grid_text_image_cards_v1
 *  - grid_text_image_cards
 *
 * Executive Feature & Tri-Fold Gallery:
 *  - Top-Left: High-contrast Feature Narrative (Title & Body)
 *  - Top-Right: Executive Spotlight Takeaway Card (Container + Avatar/Badge + Subheading + Caption)
 *  - Bottom: 3 Equal, Balanced, Beautifully Framed Portrait Image Cards
 *  - Full placement schema compliance ({ x, y, width, height, rotation: 0, opacity: 1 })
 *  - Heading shifted up comfortably with clipToSlot: false so text never clips
 *  - Preserves user uploaded image URLs/src
 */

const GRID_TEXT_IMAGE_CARDS_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Feature narrative (Top-Left)
  featureTitleX: 48,
  featureTitleY: 18,
  featureTitleW: 548,
  featureTitleH: 52,

  featureBodyX: 48,
  featureBodyY: 72,
  featureBodyW: 548,
  featureBodyH: 48,

  // Spotlight Key Point Card (Top-Right)
  pointCard: {
    x: 620,
    y: 16,
    w: 332,
    h: 104,
    radius: 14,
  },
  pointImage: {
    x: 636,
    y: 32,
    w: 72,
    h: 72,
    radius: 10,
  },
  pointTitle: {
    x: 722,
    y: 30,
    w: 214,
    h: 26,
  },
  pointBody: {
    x: 722,
    y: 58,
    w: 214,
    h: 48,
  },

  // Tri-Fold Gallery Cards (Bottom)
  galleryY: 136,
  galleryH: 390,
  cardW: 288,
  cardGap: 20,
  cardRadius: 14,

  card1: { x: 48, y: 136, w: 288, h: 390, radius: 14 },
  card2: { x: 356, y: 136, w: 288, h: 390, radius: 14 },
  card3: { x: 664, y: 136, w: 288, h: 390, radius: 14 },
};

const GRID_TEXT_IMAGE_CARDS_THEMES = [
  {
    primary: '#4F46E5', // Indigo
    accent: '#818CF8',
    tint: '#EEF2FF',
    border: '#C7D2FE',
    visualGradStart: '#EEF2FF',
    visualGradEnd: '#E0E7FF',
  },
  {
    primary: '#0D9488', // Teal
    accent: '#14B8A6',
    tint: '#F0FDFA',
    border: '#CCFBF1',
    visualGradStart: '#F0FDFA',
    visualGradEnd: '#CCFBF1',
  },
  {
    primary: '#0284C7', // Sky Blue
    accent: '#38BDF8',
    tint: '#F0F9FF',
    border: '#BAE6FD',
    visualGradStart: '#F0F9FF',
    visualGradEnd: '#E0F2FE',
  },
  {
    primary: '#D97706', // Amber
    accent: '#FBBF24',
    tint: '#FFFBEB',
    border: '#FDE68A',
    visualGradStart: '#FFFBEB',
    visualGradEnd: '#FEF3C7',
  },
];

const GRID_TEXT_IMAGE_CARDS_DEFAULTS = {
  FEATURE_TITLE: 'Describe this feature',
  FEATURE_BODY: 'Supporting paragraph with scannable copy that explains the key idea without overwhelming the slide.',
  POINT_TITLE: 'Key takeaway',
  POINT_BODY: 'Essential highlights summarizing this core capability.',
};

function isGridTextImageCardsLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase();
  return (
    id === 'grid_text_image_cards_v1' ||
    id === 'grid_text_image_cards'
  );
}

/**
 * Builds SVG visual placeholder graphic for empty image frames
 */
function buildTextImageCardsPlaceholderSvg(cardIdx, width, height, radius = 14) {
  const theme = GRID_TEXT_IMAGE_CARDS_THEMES[cardIdx % GRID_TEXT_IMAGE_CARDS_THEMES.length];
  const { primary, border, visualGradStart, visualGradEnd } = theme;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <defs>
      <linearGradient id="ticgrad-${cardIdx}" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="${visualGradStart}" />
        <stop offset="100%" stop-color="${visualGradEnd}" />
      </linearGradient>
    </defs>
    <rect x="1" y="1" width="${width - 2}" height="${height - 2}" rx="${radius}" fill="url(#ticgrad-${cardIdx})" stroke="${border}" stroke-width="1.2" />
    <g transform="translate(${width / 2 - 18}, ${height / 2 - 16})" opacity="0.4">
      <rect x="2" y="5" width="32" height="24" rx="4" fill="none" stroke="${primary}" stroke-width="2" />
      <circle cx="18" cy="17" r="6" fill="none" stroke="${primary}" stroke-width="2" />
      <path d="M 11 5 L 14 2 L 22 2 L 25 5 Z" fill="none" stroke="${primary}" stroke-width="2" />
    </g>
  </svg>`;
}

/**
 * Builds SVG visual placeholder for the spotlight point thumbnail
 */
function buildSpotlightThumbSvg(width, height, radius = 10) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <rect x="1" y="1" width="${width - 2}" height="${height - 2}" rx="${radius}" fill="#EEF2FF" stroke="#C7D2FE" stroke-width="1.2" />
    <g transform="translate(${width / 2 - 14}, ${height / 2 - 14})" opacity="0.5">
      <circle cx="14" cy="14" r="10" fill="none" stroke="#4F46E5" stroke-width="2" />
      <path d="M 10 14 L 13 17 L 19 11" fill="none" stroke="#4F46E5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
    </g>
  </svg>`;
}

/**
 * Main layout compiler for Grid Text Image Cards (Backend)
 */
function layoutGridTextImageCards(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const canvasW = canvas.width || docOrElements?.canvas?.width || 1920;
  const canvasH = canvas.height || docOrElements?.canvas?.height || 1080;
  const geom = GRID_TEXT_IMAGE_CARDS_GEOM;

  const scaleX = canvasW / geom.viewW;
  const scaleY = canvasH / geom.viewH;

  // 1. Extract existing text content
  const findText = (matcher, fallback) => {
    const el = elements.find((e) => {
      const sid = String(e.slotId || '').toUpperCase();
      const role = String(e.role || '').toUpperCase();
      return matcher(sid, role);
    });
    const txt = el?.content?.text || el?.text || el?.content?.heading || el?.content?.title;
    return txt && String(txt).trim().length > 0 ? String(txt).trim() : fallback;
  };

  const featureTitle = findText(
    (s, r) => s === 'FEATURE_TITLE' || s === 'HEADING' || s.includes('TITLE') || r === 'HEADING',
    GRID_TEXT_IMAGE_CARDS_DEFAULTS.FEATURE_TITLE
  );

  const featureBody = findText(
    (s, r) => s === 'FEATURE_BODY' || s === 'SUBTITLE' || s.includes('BODY') || r === 'SUBHEADING',
    GRID_TEXT_IMAGE_CARDS_DEFAULTS.FEATURE_BODY
  );

  const pointTitle = findText(
    (s) => s === 'POINT_TITLE' || s === 'POINT_HEADING' || s.includes('POINT'),
    GRID_TEXT_IMAGE_CARDS_DEFAULTS.POINT_TITLE
  );

  const pointBody = findText(
    (s) => s === 'POINT_BODY' || s === 'POINT_DESC' || s === 'POINT_TEXT',
    GRID_TEXT_IMAGE_CARDS_DEFAULTS.POINT_BODY
  );

  // 2. Extract existing images (preserve uploaded media)
  const existingImages = elements.filter(
    (e) => e.type === 'image' || /^(IMAGE_\d+|POINT_IMAGE)$/i.test(String(e.slotId || ''))
  );

  const getImageContent = (slotId, fallbackIdx) => {
    const el =
      elements.find((e) => String(e.slotId || '').toUpperCase() === slotId.toUpperCase()) ||
      existingImages[fallbackIdx];

    const url = el?.content?.url || el?.content?.src || el?.url || el?.src || null;
    return {
      url,
      fit: el?.content?.fit || 'cover',
      borderRadius: 14,
      name: el?.content?.name || slotId,
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
          align: config.align || 'left',
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
          fit: imgData.fit || 'cover',
          borderRadius: imgData.borderRadius || 14,
          name: imgData.name || config.slotId,
          ...(imgData.url ? {} : {
            placeholderSvg: config.placeholderSvg || buildTextImageCardsPlaceholderSvg(config.cardIdx || 0, width, height, 14),
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
          borderRadius: config.borderRadius || 14,
          svgContent: config.svgContent || null,
        },
      });
    }
  };

  // 1. Bottom Tri-Fold Gallery Images (layer: 2)
  const galleryCards = [
    { slotId: 'IMAGE_1', cardIdx: 0, geom: geom.card1 },
    { slotId: 'IMAGE_2', cardIdx: 1, geom: geom.card2 },
    { slotId: 'IMAGE_3', cardIdx: 2, geom: geom.card3 },
  ];

  galleryCards.forEach((card, idx) => {
    const imgData = getImageContent(card.slotId, idx);
    pushElement({
      id: `gtic_img_${idx + 1}`,
      type: 'image',
      slotId: card.slotId,
      cardIdx: card.cardIdx,
      layer: 2,
      imgData,
      x: card.geom.x * scaleX,
      y: card.geom.y * scaleY,
      width: card.geom.w * scaleX,
      height: card.geom.h * scaleY,
    });
  });

  // 2. Spotlight Point Card Background Container (layer: 1)
  pushElement({
    id: 'gtic_point_card_bg',
    type: 'shape',
    slotId: 'POINT_CARD_BG',
    role: 'decoration',
    layer: 1,
    x: geom.pointCard.x * scaleX,
    y: geom.pointCard.y * scaleY,
    width: geom.pointCard.w * scaleX,
    height: geom.pointCard.h * scaleY,
    fill: '#F8FAFC',
    stroke: '#E2E8F0',
    strokeWidth: 1.2,
    borderRadius: 14,
  });

  // 3. Spotlight Point Image (layer: 2)
  const pointImgData = getImageContent('POINT_IMAGE', 3);
  pushElement({
    id: 'gtic_point_img',
    type: 'image',
    slotId: 'POINT_IMAGE',
    layer: 2,
    imgData: pointImgData,
    placeholderSvg: buildSpotlightThumbSvg(Math.round(geom.pointImage.w * scaleX), Math.round(geom.pointImage.h * scaleY), 10),
    x: geom.pointImage.x * scaleX,
    y: geom.pointImage.y * scaleY,
    width: geom.pointImage.w * scaleX,
    height: geom.pointImage.h * scaleY,
  });

  // 4. Feature Title (layer: 10)
  pushElement({
    id: 'gtic_feature_title',
    type: 'text',
    slotId: 'FEATURE_TITLE',
    role: 'heading',
    layer: 10,
    text: featureTitle,
    x: geom.featureTitleX * scaleX,
    y: geom.featureTitleY * scaleY,
    width: geom.featureTitleW * scaleX,
    height: geom.featureTitleH * scaleY,
    fontSize: 25,
    fontWeight: 800,
    color: '#0F172A',
    lineHeight: 1.2,
  });

  // 5. Feature Body (layer: 10)
  pushElement({
    id: 'gtic_feature_body',
    type: 'text',
    slotId: 'FEATURE_BODY',
    role: 'body',
    layer: 10,
    text: featureBody,
    x: geom.featureBodyX * scaleX,
    y: geom.featureBodyY * scaleY,
    width: geom.featureBodyW * scaleX,
    height: geom.featureBodyH * scaleY,
    fontSize: 13,
    fontWeight: 400,
    color: '#64748B',
    lineHeight: 1.4,
  });

  // 6. Point Title (layer: 10)
  pushElement({
    id: 'gtic_point_title',
    type: 'text',
    slotId: 'POINT_TITLE',
    role: 'heading',
    layer: 10,
    text: pointTitle,
    x: geom.pointTitle.x * scaleX,
    y: geom.pointTitle.y * scaleY,
    width: geom.pointTitle.w * scaleX,
    height: geom.pointTitle.h * scaleY,
    fontSize: 14,
    fontWeight: 700,
    color: '#0F172A',
    lineHeight: 1.2,
  });

  // 7. Point Body (layer: 10)
  pushElement({
    id: 'gtic_point_body',
    type: 'text',
    slotId: 'POINT_BODY',
    role: 'body',
    layer: 10,
    text: pointBody,
    x: geom.pointBody.x * scaleX,
    y: geom.pointBody.y * scaleY,
    width: geom.pointBody.w * scaleX,
    height: geom.pointBody.h * scaleY,
    fontSize: 11,
    fontWeight: 400,
    color: '#64748B',
    lineHeight: 1.35,
  });

  if (Array.isArray(docOrElements)) {
    return outElements;
  }
  return { ...docOrElements, elements: outElements };
}

module.exports = {
  GRID_TEXT_IMAGE_CARDS_GEOM,
  GRID_TEXT_IMAGE_CARDS_THEMES,
  GRID_TEXT_IMAGE_CARDS_DEFAULTS,
  isGridTextImageCardsLayout,
  layoutGridTextImageCards,
  buildTextImageCardsPlaceholderSvg,
  buildSpotlightThumbSvg,
};
