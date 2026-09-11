/**
 * Eight Short Texts Image Layout Engine (Backend Server-Side Compiler)
 * Layout IDs: eight_short_texts_image_v1, eight_short_texts_image_right_v1
 *
 * Modern executive 8-point capability grid (2 cols x 4 rows)
 * alongside a right-hand featured hero showcase container.
 * Total elements: 28 (3 header + 8 card SVGs + 8 titles + 8 descriptions + 1 image) <= 50 limit
 */

const EIGHT_SHORT_TEXTS_IMAGE_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Header Area (Default: on Right)
  badgeX: 408,
  badgeY: 20,
  badgeW: 180,
  badgeH: 22,

  headingX: 408,
  headingY: 46,
  headingW: 548,
  headingH: 34,

  subtitleX: 408,
  subtitleY: 82,
  subtitleW: 548,
  subtitleH: 22,

  // Grid (Default: on Right for eight_short_texts_image_v1)
  gridStartX: 408,
  gridStartY: 118,
  cardW: 266,
  cardH: 94,
  colGap: 16,
  rowGap: 12,
  cardRadius: 12,

  // Image (Default: on Left for eight_short_texts_image_v1)
  imageX: 44,
  imageY: 118,
  imageW: 342,
  imageH: 412,
  imageRadius: 16,
};

function resolveEightShortTextsGeom(isRight = false) {
  if (isRight) {
    return {
      viewW: 1000,
      viewH: 560,
      badgeX: 44,
      badgeY: 20,
      badgeW: 180,
      badgeH: 22,
      headingX: 44,
      headingY: 46,
      headingW: 552,
      headingH: 34,
      subtitleX: 44,
      subtitleY: 82,
      subtitleW: 552,
      subtitleH: 22,
      gridStartX: 44,
      gridStartY: 118,
      cardW: 266,
      cardH: 94,
      colGap: 16,
      rowGap: 12,
      cardRadius: 12,
      imageX: 614,
      imageY: 118,
      imageW: 342,
      imageH: 412,
      imageRadius: 16,
    };
  }

  return EIGHT_SHORT_TEXTS_IMAGE_GEOM;
}

function isEightShortTextsRightVariant(layoutId, schema = {}) {
  const id = String(layoutId || schema?.layout_id || schema?.layoutId || '').toLowerCase();
  const variant = String(schema?.preview?.gridVariant || schema?.gridVariant || '').toLowerCase();
  return id.includes('right') || variant === 'right';
}

const EIGHT_SHORT_TEXTS_IMAGE_PALETTE = {
  primary: '#2563EB',
  accent: '#7C3AED',
  bgCard: '#FFFFFF',
  border: '#E2E8F0',
  textDark: '#0F172A',
  textMuted: '#64748B',
  badgeBg: '#EFF6FF',
  badgeText: '#2563EB',
};

const EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS = {
  BADGE: 'CORE CAPABILITIES',
  HEADING: 'Eight key points',
  SUBTITLE: 'Strategic operational framework and execution architecture',

  POINT_1_TITLE: 'Strategic planning',
  POINT_1_DESC: 'Comprehensive roadmapping and KPI alignment across initiatives.',

  POINT_2_TITLE: 'Resource optimization',
  POINT_2_DESC: 'Maximizing team throughput and capital deployment efficiency.',

  POINT_3_TITLE: 'Rapid deployment',
  POINT_3_DESC: 'Automated CI/CD pipelines delivering zero-downtime updates.',

  POINT_4_TITLE: 'Enterprise security',
  POINT_4_DESC: 'End-to-end encryption with granular compliance enforcement.',

  POINT_5_TITLE: 'Global telemetry',
  POINT_5_DESC: 'Real-time observability and predictive fault detection network.',

  POINT_6_TITLE: 'Data analytics',
  POINT_6_DESC: 'Transforming high-frequency telemetry into business insights.',

  POINT_7_TITLE: 'Automated workflow',
  POINT_7_DESC: 'Autonomous orchestration replacing manual operational toil.',

  POINT_8_TITLE: 'Continuous support',
  POINT_8_DESC: 'Round-the-clock proactive monitoring and incident handling.',

  DEFAULT_IMAGE:
    'https://images.unsplash.com/photo-1498050108023-c5249f4df085?auto=format&fit=crop&w=1200&q=80',
};

function isEightShortTextsImageLayout(layoutId) {
  const id = String(layoutId || '').trim().toLowerCase();
  return (
    id === 'eight_short_texts_image_v1' ||
    id === 'eight_short_texts_image_right_v1' ||
    id === 'eight_short_texts'
  );
}

function buildPointCardSvg(num, titleColor, accentColor, width, height) {
  const numStr = String(num).padStart(2, '0');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="100%" height="100%">
    <defs>
      <filter id="csh-${num}" x="-5%" y="-5%" width="110%" height="120%" filterUnits="userSpaceOnUse">
        <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="#0F172A" flood-opacity="0.04" />
      </filter>
    </defs>
    <!-- Card Container -->
    <rect width="${width}" height="${height}" rx="12" fill="#FFFFFF" stroke="#E2E8F0" stroke-width="1.5" filter="url(#csh-${num})" />
    <!-- Left Accent Pill -->
    <rect x="1" y="16" width="3" height="${height - 32}" rx="1.5" fill="${accentColor}" />
    <!-- Number Tag Badge -->
    <rect x="14" y="16" width="34" height="34" rx="8" fill="${accentColor}" fill-opacity="0.12" />
    <text x="31" y="38" text-anchor="middle" fill="${accentColor}" font-size="13" font-weight="800" font-family="Inter, system-ui, sans-serif">${numStr}</text>
  </svg>`;
}

function layoutEightShortTextsImage(elements = [], schema = {}, palette = {}, canvas = {}) {
  const isRight = isEightShortTextsRightVariant(schema?.layout_id || schema?.id || schema?.layoutId, schema);
  const g = resolveEightShortTextsGeom(isRight);
  const canvasW = canvas.width || 1000;
  const canvasH = canvas.height || 560;
  const scaleX = canvasW / g.viewW;
  const scaleY = canvasH / g.viewH;

  const prevBySlot = new Map();
  for (const el of elements) {
    if (el?.slotId) {
      prevBySlot.set(String(el.slotId).toUpperCase(), el);
    }
  }

  const getPrevText = (slotId, fallback = '') => {
    const el = prevBySlot.get(String(slotId).toUpperCase());
    if (typeof el?.content?.text === 'string' && el.content.text.trim()) {
      return el.content.text;
    }
    if (typeof el?.content === 'string' && el.content.trim()) {
      return el.content;
    }
    return fallback;
  };

  const getPrevImage = (slotId, fallback = '') => {
    const el = prevBySlot.get(String(slotId).toUpperCase());
    if (el?.content?.url) return el.content.url;
    if (el?.content?.src) return el.content.src;
    return fallback;
  };

  const primaryColor = palette?.primary || EIGHT_SHORT_TEXTS_IMAGE_PALETTE.primary;
  const accentColor = palette?.accent || EIGHT_SHORT_TEXTS_IMAGE_PALETTE.accent;
  const textColor = palette?.text || EIGHT_SHORT_TEXTS_IMAGE_PALETTE.textDark;
  const mutedColor = palette?.muted || EIGHT_SHORT_TEXTS_IMAGE_PALETTE.textMuted;

  const newElements = [];
  let seq = 0;
  const newId = (p) => `est-${p}-${Date.now()}-${++seq}`;

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

  // 1. Tag Badge
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
      text: getPrevText('TAG_BADGE', EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS.BADGE),
      fontSize: 11,
      fontWeight: 700,
      color: primaryColor,
      letterSpacing: '0.08em',
      clipToSlot: false,
    },
  });

  // 2. Heading
  pushElement({
    id: prevBySlot.get('HEADING')?.id || newId('heading'),
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
        getPrevText('TITLE', '') ||
        getPrevText('MAIN_TITLE', '') ||
        EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS.HEADING,
      fontSize: 26,
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
        getPrevText('BODY', '') ||
        EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS.SUBTITLE,
      fontSize: 13,
      fontWeight: 500,
      color: mutedColor,
      clipToSlot: false,
    },
  });

  // 4. 8 Point Cards
  for (let i = 1; i <= 8; i += 1) {
    const colIdx = (i - 1) % 2;
    const rowIdx = Math.floor((i - 1) / 2);

    const cardX = g.gridStartX + colIdx * (g.cardW + g.colGap);
    const cardY = g.gridStartY + rowIdx * (g.cardH + g.rowGap);

    const cardSlotId = `POINT_${i}_CARD`;
    const titleSlotId = `POINT_${i}_TITLE`;
    const legacyLabelSlotId = `POINT_${i}_LABEL`;
    const descSlotId = `POINT_${i}_DESC`;

    const activeColor = i % 2 === 1 ? primaryColor : accentColor;

    // Card SVG
    const cardSvg = buildPointCardSvg(i, textColor, activeColor, g.cardW, g.cardH);
    pushElement({
      id: prevBySlot.get(cardSlotId)?.id || newId(`est-c${i}-bg`),
      type: 'graphic',
      slotId: cardSlotId,
      layer: 2,
      rect: {
        x: cardX * scaleX,
        y: cardY * scaleY,
        width: g.cardW * scaleX,
        height: g.cardH * scaleY,
      },
      content: {
        svg: cardSvg,
        format: 'svg',
        color: activeColor,
        fill: activeColor,
      },
    });

    // Point Title
    const titleText =
      getPrevText(titleSlotId, '') ||
      getPrevText(legacyLabelSlotId, '') ||
      EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS[`POINT_${i}_TITLE`];

    pushElement({
      id: prevBySlot.get(titleSlotId)?.id || prevBySlot.get(legacyLabelSlotId)?.id || newId(`est-c${i}-title`),
      type: 'text',
      slotId: titleSlotId,
      layer: 10,
      rect: {
        x: (cardX + 56) * scaleX,
        y: (cardY + 14) * scaleY,
        width: (g.cardW - 68) * scaleX,
        height: 22 * scaleY,
      },
      content: {
        text: titleText,
        fontSize: 14,
        fontWeight: 700,
        color: textColor,
        clipToSlot: false,
      },
    });

    // Point Description
    const descText =
      getPrevText(descSlotId, '') ||
      EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS[`POINT_${i}_DESC`];

    pushElement({
      id: prevBySlot.get(descSlotId)?.id || newId(`est-c${i}-desc`),
      type: 'text',
      slotId: descSlotId,
      layer: 10,
      rect: {
        x: (cardX + 56) * scaleX,
        y: (cardY + 38) * scaleY,
        width: (g.cardW - 68) * scaleX,
        height: 44 * scaleY,
      },
      content: {
        text: descText,
        fontSize: 11.5,
        fontWeight: 400,
        color: mutedColor,
        clipToSlot: false,
      },
    });
  }

  // 5. Featured Hero Image Container (Right Showcase)
  const heroSlotId = 'HERO_IMAGE';
  const imgUrl =
    getPrevImage(heroSlotId, '') ||
    getPrevImage('IMAGE', '') ||
    EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS.DEFAULT_IMAGE;

  pushElement({
    id: prevBySlot.get(heroSlotId)?.id || newId('hero-img'),
    type: 'image',
    slotId: heroSlotId,
    layer: 3,
    rect: {
      x: g.imageX * scaleX,
      y: g.imageY * scaleY,
      width: g.imageW * scaleX,
      height: g.imageH * scaleY,
    },
    content: {
      url: imgUrl,
      src: imgUrl,
      fit: 'cover',
      borderRadius: g.imageRadius * scaleX,
    },
  });

  return newElements;
}

module.exports = {
  EIGHT_SHORT_TEXTS_IMAGE_GEOM,
  EIGHT_SHORT_TEXTS_IMAGE_PALETTE,
  EIGHT_SHORT_TEXTS_IMAGE_DEFAULTS,
  isEightShortTextsImageLayout,
  isEightShortTextsRightVariant,
  resolveEightShortTextsGeom,
  buildPointCardSvg,
  layoutEightShortTextsImage,
};
