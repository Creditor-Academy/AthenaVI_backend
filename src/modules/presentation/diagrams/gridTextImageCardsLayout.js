/**
 * Grid Text Image Cards Layout Engine (Backend Server-Side Compiler)
 * Layout IDs:
 *  - grid_text_image_cards_v1
 *  - grid_text_image_cards
 *
 * Executive Feature & Tri-Fold Gallery (matching reference design):
 *  - Top-Left:
 *    - Blue horizontal accent bar
 *    - High-contrast Feature Headline ("Describe this feature")
 *    - Supporting paragraph text (3-4 lines of scannable copy)
 *  - Top-Right:
 *    - Rounded spotlight card container
 *    - Left: Circular badge with landscape photo glyph (POINT_IMAGE)
 *    - Vertical divider line
 *    - Eyebrow tag ("KEY TAKEAWAY")
 *    - Spotlight body text ("Essential highlights summarizing this core capability.")
 *  - Bottom:
 *    - 3 Equal, beautifully balanced landscape/portrait image cards (IMAGE_1, IMAGE_2, IMAGE_3)
 *    - Soft pastel gradient with centered landscape mountain-sun placeholder glyph
 *    - Full image preservation when photos are uploaded
 *  - Ambient corner decoration curves (top-left & bottom-right)
 */

const GRID_TEXT_IMAGE_CARDS_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Ambient Corner Waves
  decorBottomRight: { x: 740, y: 440, w: 260, h: 120 },

  // Top-Left Header Area
  accentBar: {
    x: 48,
    y: 36,
    w: 48,
    h: 4,
  },
  featureTitleX: 48,
  featureTitleY: 50,
  featureTitleW: 470,
  featureTitleH: 32,

  featureBodyX: 48,
  featureBodyY: 92,
  featureBodyW: 470,
  featureBodyH: 60,

  // Top-Right Spotlight Key Takeaway Card
  pointCard: {
    x: 540,
    y: 40,
    w: 412,
    h: 164,
    radius: 18,
  },
  pointCircle: {
    x: 564,
    y: 86,
    w: 72,
    h: 72,
    radius: 36,
  },
  pointDivider: {
    x: 654,
    y: 62,
    w: 1.2,
    h: 120,
  },
  pointTitle: {
    x: 674,
    y: 74,
    w: 260,
    h: 20,
  },
  pointBody: {
    x: 674,
    y: 100,
    w: 260,
    h: 58,
  },

  // Bottom Tri-Fold Gallery Cards
  galleryY: 248,
  galleryH: 264,
  cardW: 288,
  cardGap: 20,
  cardRadius: 16,

  card1: { x: 48, y: 248, w: 288, h: 264, radius: 16 },
  card2: { x: 356, y: 248, w: 288, h: 264, radius: 16 },
  card3: { x: 664, y: 248, w: 288, h: 264, radius: 16 },
};

const GRID_TEXT_IMAGE_CARDS_THEMES = [
  {
    primary: '#4F46E5', // Indigo
    accent: '#818CF8',
    tint: '#EEF2FF',
    border: '#C7D2FE',
    visualGradStart: '#F5F8FF',
    visualGradEnd: '#E6EDFE',
  },
  {
    primary: '#4F46E5',
    accent: '#818CF8',
    tint: '#EEF2FF',
    border: '#C7D2FE',
    visualGradStart: '#F5F8FF',
    visualGradEnd: '#E6EDFE',
  },
  {
    primary: '#4F46E5',
    accent: '#818CF8',
    tint: '#EEF2FF',
    border: '#C7D2FE',
    visualGradStart: '#F5F8FF',
    visualGradEnd: '#E6EDFE',
  },
];

const GRID_TEXT_IMAGE_CARDS_DEFAULTS = {
  FEATURE_TITLE: 'Describe this feature',
  FEATURE_BODY: 'Supporting paragraph with three to four lines of scannable copy that explains the key idea without overwhelming the slide.',
  POINT_TITLE: 'KEY TAKEAWAY',
  POINT_BODY: 'Essential highlights summarizing this core capability.',
};

function isGridTextImageCardsLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase();
  return (
    id === 'grid_text_image_cards_v1' ||
    id === 'grid_text_image_cards' ||
    id === 'grid_text_image_mosaic_v1' ||
    id === 'grid_text_image_mosaic'
  );
}

/**
 * Builds SVG visual placeholder graphic for the 3 gallery cards (matching reference landscape icon)
 */
function buildGalleryCardPlaceholderSvg(cardIdx, width, height, radius = 16) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <defs>
      <linearGradient id="gtic-bg-${cardIdx}" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#F5F8FF" />
        <stop offset="100%" stop-color="#E6EDFE" />
      </linearGradient>
    </defs>
    <rect x="1" y="1" width="${width - 2}" height="${height - 2}" rx="${radius}" fill="url(#gtic-bg-${cardIdx})" stroke="#D0DBF5" stroke-width="1.2" />
    <g transform="translate(${width / 2 - 24}, ${height / 2 - 20})" opacity="0.45">
      <rect x="2" y="4" width="44" height="32" rx="6" fill="none" stroke="#6366F1" stroke-width="2.5" />
      <circle cx="33" cy="14" r="3.5" fill="#6366F1" />
      <path d="M 6 31 L 18 19 L 27 28 L 33 22 L 42 31 Z" fill="none" stroke="#6366F1" stroke-width="2.2" stroke-linejoin="round" />
    </g>
  </svg>`;
}

/**
 * Builds SVG circular visual placeholder for the spotlight point thumbnail (matching reference)
 */
function buildSpotlightThumbSvg(width, height) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <circle cx="${width / 2}" cy="${height / 2}" r="${width / 2}" fill="#EEF2FF" />
    <g transform="translate(${width / 2 - 16}, ${height / 2 - 14})" opacity="0.6">
      <rect x="2" y="4" width="28" height="20" rx="4" fill="none" stroke="#4F46E5" stroke-width="2" />
      <circle cx="21" cy="10" r="2.5" fill="#4F46E5" />
      <path d="M 5 21 L 13 13 L 19 19 L 23 15 L 27 21 Z" fill="none" stroke="#4F46E5" stroke-width="1.8" stroke-linejoin="round" />
    </g>
  </svg>`;
}

/**
 * Main layout compiler for Grid Text Image Cards (Backend)
 */
function layoutGridTextImageCards(docOrElements, schema, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1000;
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 560;
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

  const pointTitleRaw = findText(
    (s) => s === 'POINT_TITLE' || s === 'POINT_HEADING' || (s.includes('POINT') && !s.includes('BODY') && !s.includes('IMAGE')),
    GRID_TEXT_IMAGE_CARDS_DEFAULTS.POINT_TITLE
  );
  const pointTitle = String(pointTitleRaw || 'KEY TAKEAWAY').toUpperCase();

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
      borderRadius: slotId === 'POINT_IMAGE' ? 36 : 16,
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
          clipToSlot: false, // Prevents ascender/descender clipping
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
          borderRadius: imgData.borderRadius || 16,
          name: imgData.name || config.slotId,
          ...(imgData.url ? {} : {
            placeholderSvg: config.placeholderSvg || buildGalleryCardPlaceholderSvg(config.cardIdx || 0, width, height, 16),
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
          borderRadius: config.borderRadius || 16,
          svgContent: config.svgContent || null,
        },
      });
    }
  };

  // 0. Ambient bottom-right background decoration wave (layer: 0)
  pushElement({
    id: 'gtic_decor_br',
    type: 'shape',
    slotId: 'DECOR_BR',
    role: 'decoration',
    layer: 0,
    x: geom.decorBottomRight.x * scaleX,
    y: geom.decorBottomRight.y * scaleY,
    width: geom.decorBottomRight.w * scaleX,
    height: geom.decorBottomRight.h * scaleY,
    svgContent: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 220 120" width="100%" height="100%"><path d="M 40 120 C 100 60, 160 20, 220 10 L 220 120 Z" fill="#EEF2FF" opacity="0.75" /></svg>`,
  });

  // 1. Top-Left Blue Horizontal Accent Bar (layer: 10)
  pushElement({
    id: 'gtic_accent_bar',
    type: 'shape',
    slotId: 'ACCENT_BAR',
    role: 'decoration',
    layer: 10,
    fill: '#4F46E5',
    stroke: '#4F46E5',
    borderRadius: 2,
    x: geom.accentBar.x * scaleX,
    y: geom.accentBar.y * scaleY,
    width: geom.accentBar.w * scaleX,
    height: geom.accentBar.h * scaleY,
  });

  // 2. Feature Title (layer: 10) - Straight single line, compact & clean
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
    fontSize: 17,
    fontWeight: 800,
    color: '#0B192C',
    lineHeight: 1.15,
  });

  // 3. Feature Body (layer: 10) - Plenty of breathing room below title
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
    fontSize: 10,
    fontWeight: 400,
    color: '#475569',
    lineHeight: 1.4,
  });

  // 4. Spotlight Point Card Background Container (layer: 1)
  pushElement({
    id: 'gtic_point_card_bg',
    type: 'shape',
    slotId: 'POINT_CARD_BG',
    role: 'card',
    layer: 1,
    x: geom.pointCard.x * scaleX,
    y: geom.pointCard.y * scaleY,
    width: geom.pointCard.w * scaleX,
    height: geom.pointCard.h * scaleY,
    fill: '#F8FAFF',
    stroke: '#E2E8F0',
    strokeWidth: 1.2,
    borderRadius: geom.pointCard.radius,
  });

  // 5. Spotlight Point Image (Circular Badge) (layer: 2)
  const pointImgData = getImageContent('POINT_IMAGE', 3);
  pushElement({
    id: 'gtic_point_img',
    type: 'image',
    slotId: 'POINT_IMAGE',
    layer: 2,
    imgData: pointImgData,
    placeholderSvg: buildSpotlightThumbSvg(Math.round(geom.pointCircle.w * scaleX), Math.round(geom.pointCircle.h * scaleY)),
    x: geom.pointCircle.x * scaleX,
    y: geom.pointCircle.y * scaleY,
    width: geom.pointCircle.w * scaleX,
    height: geom.pointCircle.h * scaleY,
  });

  // 6. Spotlight Divider Line (layer: 2)
  pushElement({
    id: 'gtic_point_divider',
    type: 'shape',
    slotId: 'POINT_DIVIDER',
    role: 'decoration',
    layer: 2,
    fill: '#E2E8F0',
    stroke: '#E2E8F0',
    borderRadius: 1,
    x: geom.pointDivider.x * scaleX,
    y: geom.pointDivider.y * scaleY,
    width: geom.pointDivider.w * scaleX,
    height: geom.pointDivider.h * scaleY,
  });

  // 7. Point Title / Eyebrow (layer: 10)
  pushElement({
    id: 'gtic_point_title',
    type: 'text',
    slotId: 'POINT_TITLE',
    role: 'eyebrow',
    layer: 10,
    text: pointTitle,
    x: geom.pointTitle.x * scaleX,
    y: geom.pointTitle.y * scaleY,
    width: geom.pointTitle.w * scaleX,
    height: geom.pointTitle.h * scaleY,
    fontSize: 9.5,
    fontWeight: 800,
    color: '#4F46E5',
    letterSpacing: '0.14em',
    lineHeight: 1.2,
  });

  // 8. Point Body (layer: 10)
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
    fontSize: 10.5,
    fontWeight: 500,
    color: '#1E293B',
    lineHeight: 1.35,
  });

  // 9. Bottom Tri-Fold Gallery Images (layer: 2)
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

  if (Array.isArray(docOrElements)) {
    return outElements;
  }
  return { ...docOrElements, elements: outElements };
}

/**
 * Standalone SVG preview matching the reference design exactly
 */
function gridTextImageCardsPreviewSvg(options = {}) {
  const geom = GRID_TEXT_IMAGE_CARDS_GEOM;
  const defaults = GRID_TEXT_IMAGE_CARDS_DEFAULTS;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${geom.viewW} ${geom.viewH}" width="100%" height="100%">
    <defs>
      <linearGradient id="gtic-prev-card-0" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#F5F8FF" />
        <stop offset="100%" stop-color="#E6EDFE" />
      </linearGradient>
      <linearGradient id="gtic-prev-card-1" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#F5F8FF" />
        <stop offset="100%" stop-color="#E6EDFE" />
      </linearGradient>
      <linearGradient id="gtic-prev-card-2" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#F5F8FF" />
        <stop offset="100%" stop-color="#E6EDFE" />
      </linearGradient>
      <filter id="gtic-point-shad" x="-4%" y="-6%" width="108%" height="116%" filterUnits="userSpaceOnUse">
        <feDropShadow dx="0" dy="4" stdDeviation="8" flood-color="#0F172A" flood-opacity="0.04" />
      </filter>
    </defs>

    <!-- Slide background -->
    <rect width="100%" height="100%" fill="#FFFFFF" />

    <!-- Ambient Top-Left Corner Curve -->
    <path d="M 0 0 L 70 0 C 40 25, 15 50, 0 65 Z" fill="#EEF2FF" opacity="0.4" />

    <!-- Ambient Bottom-Right Wave -->
    <path d="M 740 560 C 810 500, 890 450, 1000 430 L 1000 560 Z" fill="#EEF2FF" opacity="0.65" />

    <!-- Blue Accent Bar -->
    <rect x="${geom.accentBar.x}" y="${geom.accentBar.y}" width="${geom.accentBar.w}" height="${geom.accentBar.h}" rx="2" fill="#4F46E5" />

    <!-- Headline (1 straight line) -->
    <text x="${geom.featureTitleX}" y="${geom.featureTitleY + 22}" fill="#0B192C" font-size="20" font-weight="800" font-family="Inter, system-ui, sans-serif" letter-spacing="-0.02em">Describe this feature</text>

    <!-- Paragraph (3 lines) -->
    <text x="${geom.featureBodyX}" y="${geom.featureBodyY + 14}" fill="#475569" font-size="11" font-weight="400" font-family="Inter, system-ui, sans-serif">Supporting paragraph with three to four lines of</text>
    <text x="${geom.featureBodyX}" y="${geom.featureBodyY + 28}" fill="#475569" font-size="11" font-weight="400" font-family="Inter, system-ui, sans-serif">scannable copy that explains the key idea without</text>
    <text x="${geom.featureBodyX}" y="${geom.featureBodyY + 42}" fill="#475569" font-size="11" font-weight="400" font-family="Inter, system-ui, sans-serif">overwhelming the slide.</text>

    <!-- Spotlight Key Takeaway Card Container -->
    <rect x="${geom.pointCard.x}" y="${geom.pointCard.y}" width="${geom.pointCard.w}" height="${geom.pointCard.h}" rx="${geom.pointCard.radius}" fill="#F8FAFF" stroke="#E2E8F0" stroke-width="1.2" filter="url(#gtic-point-shad)" />

    <!-- Spotlight Circle with landscape icon -->
    <circle cx="${geom.pointCircle.x + geom.pointCircle.w / 2}" cy="${geom.pointCircle.y + geom.pointCircle.h / 2}" r="${geom.pointCircle.w / 2}" fill="#EEF2FF" />
    <g transform="translate(${geom.pointCircle.x + geom.pointCircle.w / 2 - 16}, ${geom.pointCircle.y + geom.pointCircle.h / 2 - 14})" opacity="0.65">
      <rect x="2" y="4" width="28" height="20" rx="4" fill="none" stroke="#4F46E5" stroke-width="2" />
      <circle cx="21" cy="10" r="2.5" fill="#4F46E5" />
      <path d="M 5 21 L 13 13 L 19 19 L 23 15 L 27 21 Z" fill="none" stroke="#4F46E5" stroke-width="1.8" stroke-linejoin="round" />
    </g>

    <!-- Spotlight Divider Line -->
    <line x1="${geom.pointDivider.x}" y1="${geom.pointDivider.y}" x2="${geom.pointDivider.x}" y2="${geom.pointDivider.y + geom.pointDivider.h}" stroke="#E2E8F0" stroke-width="1.2" />

    <!-- Eyebrow: KEY TAKEAWAY -->
    <text x="${geom.pointTitle.x}" y="${geom.pointTitle.y + 13}" fill="#4F46E5" font-size="10" font-weight="800" font-family="Inter, system-ui, sans-serif" letter-spacing="0.14em">${defaults.POINT_TITLE}</text>

    <!-- Point Body -->
    <text x="${geom.pointBody.x}" y="${geom.pointBody.y + 16}" fill="#1E293B" font-size="11.5" font-weight="500" font-family="Inter, system-ui, sans-serif">Essential highlights</text>
    <text x="${geom.pointBody.x}" y="${geom.pointBody.y + 34}" fill="#1E293B" font-size="11.5" font-weight="500" font-family="Inter, system-ui, sans-serif">summarizing this core...</text>

    <!-- Bottom Tri-Fold Gallery Cards -->
    <!-- Card 1 -->
    <g>
      <rect x="${geom.card1.x}" y="${geom.card1.y}" width="${geom.card1.w}" height="${geom.card1.h}" rx="${geom.card1.radius}" fill="url(#gtic-prev-card-0)" stroke="#D0DBF5" stroke-width="1.2" />
      <g transform="translate(${geom.card1.x + geom.card1.w / 2 - 24}, ${geom.card1.y + geom.card1.h / 2 - 20})" opacity="0.45">
        <rect x="2" y="4" width="44" height="32" rx="6" fill="none" stroke="#6366F1" stroke-width="2.5" />
        <circle cx="33" cy="14" r="3.5" fill="#6366F1" />
        <path d="M 6 31 L 18 19 L 27 28 L 33 22 L 42 31 Z" fill="none" stroke="#6366F1" stroke-width="2.2" stroke-linejoin="round" />
      </g>
    </g>

    <!-- Card 2 -->
    <g>
      <rect x="${geom.card2.x}" y="${geom.card2.y}" width="${geom.card2.w}" height="${geom.card2.h}" rx="${geom.card2.radius}" fill="url(#gtic-prev-card-1)" stroke="#D0DBF5" stroke-width="1.2" />
      <g transform="translate(${geom.card2.x + geom.card2.w / 2 - 24}, ${geom.card2.y + geom.card2.h / 2 - 20})" opacity="0.45">
        <rect x="2" y="4" width="44" height="32" rx="6" fill="none" stroke="#6366F1" stroke-width="2.5" />
        <circle cx="33" cy="14" r="3.5" fill="#6366F1" />
        <path d="M 6 31 L 18 19 L 27 28 L 33 22 L 42 31 Z" fill="none" stroke="#6366F1" stroke-width="2.2" stroke-linejoin="round" />
      </g>
    </g>

    <!-- Card 3 -->
    <g>
      <rect x="${geom.card3.x}" y="${geom.card3.y}" width="${geom.card3.w}" height="${geom.card3.h}" rx="${geom.card3.radius}" fill="url(#gtic-prev-card-2)" stroke="#D0DBF5" stroke-width="1.2" />
      <g transform="translate(${geom.card3.x + geom.card3.w / 2 - 24}, ${geom.card3.y + geom.card3.h / 2 - 20})" opacity="0.45">
        <rect x="2" y="4" width="44" height="32" rx="6" fill="none" stroke="#6366F1" stroke-width="2.5" />
        <circle cx="33" cy="14" r="3.5" fill="#6366F1" />
        <path d="M 6 31 L 18 19 L 27 28 L 33 22 L 42 31 Z" fill="none" stroke="#6366F1" stroke-width="2.2" stroke-linejoin="round" />
      </g>
    </g>
  </svg>`;
}

module.exports = {
  GRID_TEXT_IMAGE_CARDS_GEOM,
  GRID_TEXT_IMAGE_CARDS_THEMES,
  GRID_TEXT_IMAGE_CARDS_DEFAULTS,
  isGridTextImageCardsLayout,
  layoutGridTextImageCards,
  buildGalleryCardPlaceholderSvg,
  buildSpotlightThumbSvg,
  gridTextImageCardsPreviewSvg,
};
