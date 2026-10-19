/**
 * Table Two Desc Cards Layout (Backend Diagram Compiler)
 * Layout ID: table_two_desc_cards_v1
 * Features:
 *  - Header (Top Left): Gradient accent bar, Heading ("Compare Datasets") + Subtitle
 *  - Two Large Unified Column Cards (Dataset 1 & Dataset 2):
 *    - Left Unified Card (Blue Theme):
 *      - Header: Solid blue circle icon with white database graphic, Title ("Dataset 1"), Sub-label ("Key details and values"), Corner wave
 *      - 3x3 Table: Soft blue header bar (A, B, C) + 3 data rows (Row 1, Row 2, Row 3)
 *      - Nested Description Card (Bottom): Light blue container, lightbulb icon card, vertical divider line, Title ("Description 1"), Body text
 *    - Right Unified Card (Purple Theme):
 *      - Header: Solid purple circle icon with white database graphic, Title ("Dataset 2"), Sub-label ("Key details and values"), Corner wave
 *      - 3x3 Table: Soft purple header bar (A, B, C) + 3 data rows (Row 1, Row 2, Row 3)
 *      - Nested Description Card (Bottom): Light purple container, lightbulb icon card, vertical divider line, Title ("Description 2"), Body text
 *  - Fully theme-responsive and recolorable
 */

const TABLE_TWO_DESC_CARDS_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Header (Top Left)
  accentX: 44,
  accentY: 26,
  accentW: 36,
  accentH: 4,

  headingX: 44,
  headingY: 36,
  headingW: 800,
  headingH: 34,

  subtitleX: 44,
  subtitleY: 72,
  subtitleW: 800,
  subtitleH: 22,

  // Two Large Unified Column Cards
  cardY: 114,
  cardH: 420,
  cardW: 444,
  cardGap: 24,

  card1X: 44,
  card2X: 512,

  // Inside Unified Card Header
  iconXOffset: 20,
  iconYOffset: 18,
  iconRadius: 22,

  titleXOffset: 72,
  titleYOffset: 16,
  titleH: 24,

  subYOffset: 42,
  subH: 18,

  // Inner Table Grid
  tableXOffset: 16,
  tableYOffset: 70,
  tableW: 412,
  tableHeaderH: 34,
  rowH: 36,
  rows: 3,
  cols: 3,

  // Bottom Nested Description Sub-Card (generous height & padding so data is never clipped)
  descCardXOffset: 16,
  descCardYOffset: 278,
  descCardW: 412,
  descCardH: 124,

  descIconXOffset: 26,
  descIconYOffset: 294,
  descIconW: 46,
  descIconH: 92,

  descDividerXOffset: 84,

  descTextXOffset: 96,
  descTitleYOffset: 290,
  descTitleH: 22,
  descBodyYOffset: 314,
  descBodyH: 82,
};

const TABLE_TWO_DESC_CARDS_PALETTE = {
  // Theme 1: Sky / Ocean Blue
  t1Primary: '#2563EB',
  t1Accent: '#38BDF8',
  t1BgSub: '#F0F9FF',
  t1IconBox: '#E0F2FE',
  t1HeaderBg: '#EFF6FF',
  t1HeaderText: '#1E3A8A',
  t1Divider: '#BAE6FD',

  // Theme 2: Vibrant Purple
  t2Primary: '#9333EA',
  t2Accent: '#C084FC',
  t2BgSub: '#FAF5FF',
  t2IconBox: '#F3E8FF',
  t2HeaderBg: '#FAF5FF',
  t2HeaderText: '#581C87',
  t2Divider: '#E9D5FF',

  // Shared
  cardBg: '#FFFFFF',
  cardBorder: '#E2E8F0',
  gridBorder: '#F1F5F9',
  rowEven: '#FFFFFF',
  rowOdd: '#F8FAFC',
  textDark: '#0F172A',
  textMuted: '#64748B',
  white: '#FFFFFF',
};

const TABLE_TWO_DESC_CARDS_DEFAULTS = {
  HEADING: 'Compare Datasets',
  SUBTITLE: 'Explore the differences and similarities between the two datasets side by side for a clearer understanding.',

  // Dataset 1
  DATASET_1_TITLE: 'Dataset 1',
  TABLE_1_TITLE: 'Dataset 1',
  DATASET_1_SUB: 'Key details and values',

  T1_COL_1_HEADER: 'A',
  T1_COL_2_HEADER: 'B',
  T1_COL_3_HEADER: 'C',

  T1_ROW_1_LABEL: 'Row 1',
  T1_CELL_1_1: '—',
  T1_CELL_1_2: '—',

  T1_ROW_2_LABEL: 'Row 2',
  T1_CELL_2_1: '—',
  T1_CELL_2_2: '—',

  T1_ROW_3_LABEL: 'Row 3',
  T1_CELL_3_1: '—',
  T1_CELL_3_2: '—',

  DESC_1_TITLE: 'Description 1',
  DESC_1: 'Add a short description about Dataset 1 here. You can mention key details, purpose, or any important insights.',

  // Dataset 2
  DATASET_2_TITLE: 'Dataset 2',
  TABLE_2_TITLE: 'Dataset 2',
  DATASET_2_SUB: 'Key details and values',

  T2_COL_1_HEADER: 'A',
  T2_COL_2_HEADER: 'B',
  T2_COL_3_HEADER: 'C',

  T2_ROW_1_LABEL: 'Row 1',
  T2_CELL_1_1: '—',
  T2_CELL_1_2: '—',

  T2_ROW_2_LABEL: 'Row 2',
  T2_CELL_2_1: '—',
  T2_CELL_2_2: '—',

  T2_ROW_3_LABEL: 'Row 3',
  T2_CELL_3_1: '—',
  T2_CELL_3_2: '—',

  DESC_2_TITLE: 'Description 2',
  DESC_2: 'Add a short description about Dataset 2 here. You can mention key details, purpose, or any important insights.',
};

function isTableTwoDescCardsLayout(layoutId) {
  const s = String(layoutId || '').toLowerCase();
  return (
    s === 'table_two_desc_cards_v1' ||
    s === 'table_two_desc_cards' ||
    s === 'table_dual_cards'
  );
}

// White Outline Database Stack (for solid circle)
const dbIconWhite = `
  <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
    <ellipse cx="12" cy="5" rx="9" ry="3"/>
    <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
    <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
  </svg>
`;

// Outline Lightbulb
const bulbIconSvg = (color = 'currentColor') => `
  <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M9 18h6"/>
    <path d="M10 22h4"/>
    <path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"/>
  </svg>
`;

/**
 * Builds vector SVG for a single unified card.
 * Uses currentColor with opacities so that when the user picks ANY color,
 * the card immediately and beautifully recolors in real time.
 */
function buildSingleCardSvg({ color = '#2563EB', isT1 = true }) {
  const g = TABLE_TWO_DESC_CARDS_GEOM;
  const w = g.cardW;
  const h = g.cardH;

  const iconCx = g.iconXOffset + g.iconRadius;
  const iconCy = g.iconYOffset + g.iconRadius;

  const tableX = g.tableXOffset;
  const tableY = g.tableYOffset;
  const colW = g.tableW / g.cols;

  let innerTable = `
    <!-- Table Header Bar -->
    <rect x="${tableX}" y="${tableY}" width="${g.tableW}" height="${g.tableHeaderH}" rx="8" fill="currentColor" fill-opacity="0.10" />
  `;

  // Table Row dividers & backgrounds
  for (let r = 0; r < g.rows; r += 1) {
    const rowY = tableY + g.tableHeaderH + r * g.rowH;
    const isEven = r % 2 === 0;
    const rowBg = isEven ? '#FFFFFF' : '#F8FAFC';

    innerTable += `
      <rect x="${tableX}" y="${rowY}" width="${g.tableW}" height="${g.rowH}" fill="${rowBg}" />
      <line x1="${tableX}" y1="${rowY + g.rowH}" x2="${tableX + g.tableW}" y2="${rowY + g.rowH}" stroke="#F1F5F9" stroke-width="1" />
    `;
  }

  // Vertical column divider lines
  for (let c = 1; c < g.cols; c += 1) {
    const divX = tableX + c * colW;
    innerTable += `
      <line x1="${divX}" y1="${tableY}" x2="${divX}" y2="${tableY + g.tableHeaderH + g.rows * g.rowH}" stroke="#F1F5F9" stroke-width="1" />
    `;
  }

  const descCardX = g.descCardXOffset;
  const descCardY = g.descCardYOffset;
  const descIconX = g.descIconXOffset;
  const descIconY = g.descIconYOffset;
  const descDividerX = g.descDividerXOffset;

  const clipId = isT1 ? 'c1LocalClip' : 'c2LocalClip';

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" fill="none" color="${color}">
    <defs>
      <clipPath id="${clipId}">
        <rect x="0" y="0" width="${w}" height="${h}" rx="16" />
      </clipPath>
    </defs>

    <!-- Outer Unified Card clipped content -->
    <g clip-path="url(#${clipId})">
      <rect x="0" y="0" width="${w}" height="${h}" rx="16" fill="#FFFFFF" />

      <!-- Top-Right Organic Corner Wave inside Card -->
      <path d="M ${w - 130} 0 C ${w - 70} 45, ${w - 25} 75, ${w} 115 L ${w} 0 Z" fill="currentColor" fill-opacity="0.12" />

      <!-- Bottom-Right Subtle Organic Wave inside Card -->
      <path d="M ${w - 90} ${h} C ${w - 45} ${h - 35}, ${w - 18} ${h - 52}, ${w} ${h - 70} L ${w} ${h} Z" fill="currentColor" fill-opacity="0.06" />

      <!-- Solid Circle Icon with White Database Stack -->
      <circle cx="${iconCx}" cy="${iconCy}" r="${g.iconRadius}" fill="currentColor" />
      <g transform="translate(${iconCx - 11}, ${iconCy - 11})">
        ${dbIconWhite}
      </g>

      <!-- Inner Table Grid -->
      <g>
        ${innerTable}
      </g>

      <!-- Nested Description Card Container -->
      <rect x="${descCardX}" y="${descCardY}" width="${g.descCardW}" height="${g.descCardH}" rx="12" fill="currentColor" fill-opacity="0.06" stroke="currentColor" stroke-opacity="0.12" stroke-width="1" />

      <!-- Rounded Lightbulb Icon Box -->
      <rect x="${descIconX}" y="${descIconY}" width="${g.descIconW}" height="${g.descIconH}" rx="10" fill="currentColor" fill-opacity="0.14" />
      <g transform="translate(${descIconX + (g.descIconW - 22) / 2}, ${descIconY + (g.descIconH - 22) / 2})">
        ${bulbIconSvg('currentColor')}
      </g>

      <!-- Vertical Divider Line -->
      <line x1="${descDividerX}" y1="${descIconY + 6}" x2="${descDividerX}" y2="${descIconY + g.descIconH - 6}" stroke="currentColor" stroke-opacity="0.30" stroke-width="1.5" />
    </g>

    <!-- Outer Card Border (rendered crisp on top of clip) -->
    <rect x="0.5" y="0.5" width="${w - 1}" height="${h - 1}" rx="16" fill="none" stroke="currentColor" stroke-opacity="0.22" stroke-width="1.2" />
  </svg>`;
}

/**
 * Slide background top accent bar & subtle organic waves
 */
function buildSlideDecoSvg(t1Color = '#2563EB', t2Color = '#9333EA') {
  const g = TABLE_TWO_DESC_CARDS_GEOM;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" fill="none">
    <defs>
      <linearGradient id="tbl2DescCardsAccent" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="${t1Color}" />
        <stop offset="100%" stop-color="${t2Color}" />
      </linearGradient>
      <linearGradient id="t1SlideBlob" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="${t1Color}" stop-opacity="0.18" />
        <stop offset="100%" stop-color="${t2Color}" stop-opacity="0.04" />
      </linearGradient>
    </defs>

    <!-- Slide background top-right organic wave -->
    <path d="M860 0 C930 10, 970 40, 1000 110 L1000 0 Z" fill="url(#t1SlideBlob)" />

    <!-- Accent pill -->
    <rect x="${g.accentX}" y="${g.accentY}" width="${g.accentW}" height="${g.accentH}" rx="2" fill="url(#tbl2DescCardsAccent)" />
  </svg>`;
}

/**
 * Builds vector SVG Chrome with both unified cards and slide decorations combined.
 * Used for preview thumbnails and export.
 */
function buildTableTwoDescCardsSvgChrome(palette = TABLE_TWO_DESC_CARDS_PALETTE) {
  const g = TABLE_TWO_DESC_CARDS_GEOM;
  const t1Color = palette.t1Primary || TABLE_TWO_DESC_CARDS_PALETTE.t1Primary;
  const t2Color = palette.t2Primary || TABLE_TWO_DESC_CARDS_PALETTE.t2Primary;

  const slideDeco = buildSlideDecoSvg(t1Color, t2Color);
  const card1Svg = buildSingleCardSvg({ color: t1Color, isT1: true });
  const card2Svg = buildSingleCardSvg({ color: t2Color, isT1: false });

  const extractInner = (svgStr) => {
    const match = String(svgStr || '').match(/<svg[^>]*>([\s\S]*)<\/svg>/i);
    return match ? match[1] : svgStr;
  };

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" fill="none">
    ${extractInner(slideDeco)}
    <g transform="translate(${g.card1X}, ${g.cardY})">
      ${extractInner(card1Svg)}
    </g>
    <g transform="translate(${g.card2X}, ${g.cardY})">
      ${extractInner(card2Svg)}
    </g>
  </svg>`;
}

function tableTwoDescCardsChromeSpecs(palette = TABLE_TWO_DESC_CARDS_PALETTE) {
  const g = TABLE_TWO_DESC_CARDS_GEOM;
  const t1Color = palette.t1Primary || TABLE_TWO_DESC_CARDS_PALETTE.t1Primary;
  const t2Color = palette.t2Primary || TABLE_TWO_DESC_CARDS_PALETTE.t2Primary;
  return [
    {
      slotId: 'TABLE_TWO_DESC_CARDS_CHROME',
      kind: 'slideDeco',
      x: 0,
      y: 0,
      w: g.viewW,
      h: g.viewH,
      layer: 2,
    },
    {
      slotId: 'T1_CARD_CHROME',
      kind: 'card1',
      x: g.card1X,
      y: g.cardY,
      w: g.cardW,
      h: g.cardH,
      layer: 4,
      color: t1Color,
    },
    {
      slotId: 'T2_CARD_CHROME',
      kind: 'card2',
      x: g.card2X,
      y: g.cardY,
      w: g.cardW,
      h: g.cardH,
      layer: 4,
      color: t2Color,
    },
  ];
}

function tableTwoDescCardsOverlay(canvasW, canvasH) {
  const g = TABLE_TWO_DESC_CARDS_GEOM;
  const sx = canvasW / g.viewW;
  const sy = canvasH / g.viewH;

  // Top Header
  const heading = {
    x: Math.round(g.headingX * sx),
    y: Math.round(g.headingY * sy),
    width: Math.round(g.headingW * sx),
    height: Math.round(g.headingH * sy),
  };

  const subtitle = {
    x: Math.round(g.subtitleX * sx),
    y: Math.round(g.subtitleY * sy),
    width: Math.round(g.subtitleW * sx),
    height: Math.round(g.subtitleH * sy),
  };

  const buildUnifiedCardOverlay = (cardX) => {
    const title = {
      x: Math.round((cardX + g.titleXOffset) * sx),
      y: Math.round((g.cardY + g.titleYOffset) * sy),
      width: Math.round((g.cardW - g.titleXOffset - 20) * sx),
      height: Math.round(g.titleH * sy),
    };

    const sub = {
      x: Math.round((cardX + g.titleXOffset) * sx),
      y: Math.round((g.cardY + g.subYOffset) * sy),
      width: Math.round((g.cardW - g.titleXOffset - 20) * sx),
      height: Math.round(g.subH * sy),
    };

    const tableX = cardX + g.tableXOffset;
    const tableY = g.cardY + g.tableYOffset;
    const colW = g.tableW / g.cols;

    // 3 Column Headers
    const headers = [];
    for (let c = 0; c < g.cols; c += 1) {
      headers.push({
        x: Math.round((tableX + c * colW) * sx),
        y: Math.round(tableY * sy),
        width: Math.round(colW * sx),
        height: Math.round(g.tableHeaderH * sy),
      });
    }

    // 3 Rows
    const rows = [];
    for (let r = 0; r < g.rows; r += 1) {
      const rowY = tableY + g.tableHeaderH + r * g.rowH;
      const rowLabel = {
        x: Math.round((tableX + 12) * sx),
        y: Math.round(rowY * sy),
        width: Math.round((colW - 16) * sx),
        height: Math.round(g.rowH * sy),
      };

      const cell1 = {
        x: Math.round((tableX + colW) * sx),
        y: Math.round(rowY * sy),
        width: Math.round(colW * sx),
        height: Math.round(g.rowH * sy),
      };

      const cell2 = {
        x: Math.round((tableX + 2 * colW) * sx),
        y: Math.round(rowY * sy),
        width: Math.round(colW * sx),
        height: Math.round(g.rowH * sy),
      };

      rows.push({ rowLabel, cell1, cell2 });
    }

    // Nested Description Sub-Card (generous bounds, zero clipping)
    const descTitle = {
      x: Math.round((cardX + g.descTextXOffset) * sx),
      y: Math.round((g.cardY + g.descTitleYOffset) * sy),
      width: Math.round((g.cardW - g.descTextXOffset - 20) * sx),
      height: Math.round(g.descTitleH * sy),
    };

    const descBody = {
      x: Math.round((cardX + g.descTextXOffset) * sx),
      y: Math.round((g.cardY + g.descBodyYOffset) * sy),
      width: Math.round((g.cardW - g.descTextXOffset - 20) * sx),
      height: Math.round(g.descBodyH * sy),
    };

    return { title, sub, headers, rows, descTitle, descBody };
  };

  return {
    heading,
    subtitle,
    card1: buildUnifiedCardOverlay(g.card1X),
    card2: buildUnifiedCardOverlay(g.card2X),
  };
}

function specToTableTwoDescCardsContent(spec, palette = TABLE_TWO_DESC_CARDS_PALETTE) {
  const t1Color = spec.color || palette?.t1Primary || palette?.primary || TABLE_TWO_DESC_CARDS_PALETTE.t1Primary;
  const t2Color = spec.color || palette?.t2Primary || palette?.secondary || TABLE_TWO_DESC_CARDS_PALETTE.t2Primary;

  if (spec.slotId === 'T1_CARD_CHROME' || spec.kind === 'card1') {
    return {
      svg: buildSingleCardSvg({ color: t1Color, isT1: true }),
      colorMode: 'recolorable',
      fill: t1Color,
    };
  }

  if (spec.slotId === 'T2_CARD_CHROME' || spec.kind === 'card2') {
    return {
      svg: buildSingleCardSvg({ color: t2Color, isT1: false }),
      colorMode: 'recolorable',
      fill: t2Color,
    };
  }

  if (spec.slotId === 'TABLE_TWO_DESC_CARDS_CHROME' && spec.kind === 'slideDeco') {
    return {
      svg: buildSlideDecoSvg(t1Color, t2Color),
      colorMode: 'fixed',
      fill: t1Color,
    };
  }

  // Fallback for full SVG preview / legacy single slot
  return {
    svg: buildTableTwoDescCardsSvgChrome(palette),
    colorMode: 'recolorable',
    fill: t1Color,
  };
}

function tableTwoDescCardsPreviewSvg() {
  return buildTableTwoDescCardsSvgChrome(TABLE_TWO_DESC_CARDS_PALETTE);
}

/**
 * Main Layout Compiler for Table Two Desc Cards
 */
function layoutTableTwoDescCards(elements, schema, palette = {}, canvas = {}) {
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const sx = canvasW / TABLE_TWO_DESC_CARDS_GEOM.viewW;
  const sy = canvasH / TABLE_TWO_DESC_CARDS_GEOM.viewH;

  const mergedPalette = {
    ...TABLE_TWO_DESC_CARDS_PALETTE,
    ...(palette?.primary ? {
      t1Primary: palette.primary,
      t1Accent: palette.accent || '#38BDF8',
      t1BgSub: palette.primaryLight || '#F0F9FF',
      t1IconBox: palette.primaryLight || '#E0F2FE',
      t1HeaderBg: palette.primaryLight || '#EFF6FF',
      t1HeaderText: palette.primaryDark || '#1E3A8A',
      t1Divider: palette.primaryLight || '#BAE6FD',
    } : {}),
    ...(palette?.secondary ? {
      t2Primary: palette.secondary,
      t2Accent: palette.accent || '#C084FC',
      t2BgSub: palette.secondaryLight || '#FAF5FF',
      t2IconBox: palette.secondaryLight || '#F3E8FF',
      t2HeaderBg: palette.secondaryLight || '#FAF5FF',
      t2HeaderText: palette.secondaryDark || '#581C87',
      t2Divider: palette.secondaryLight || '#E9D5FF',
    } : {}),
    ...(palette?.text ? { textDark: palette.text } : {}),
    ...(palette?.muted ? { textMuted: palette.muted } : {}),
  };

  const prevBySlot = new Map();
  for (const el of elements || []) {
    const sid = String(el.slotId || el.id || '').toUpperCase();
    if (sid) prevBySlot.set(sid, el);
  }

  const newId = (prefix) => `${prefix}-${Math.random().toString(36).substr(2, 9)}`;

  const getText = (slotId, fallback, aliases = []) => {
    let match = prevBySlot.get(slotId.toUpperCase());
    if (!match && Array.isArray(aliases)) {
      for (const a of aliases) {
        match = prevBySlot.get(String(a).toUpperCase());
        if (match) break;
      }
    }
    if (!match?.content) return fallback;
    const text = typeof match.content === 'string' ? match.content : match.content.text || match.content.body;
    if (text !== undefined && text !== null) {
      const s = String(text).trim();
      if (s !== '' && s !== '●' && s !== '•' && s !== '·' && s !== '▪' && s !== '○') return s;
    }
    return fallback;
  };

  const overlay = tableTwoDescCardsOverlay(canvasW, canvasH);
  const next = [];

  const placeText = (slotId, box, style, role = 'body', fallback = '', aliases = []) => {
    const prev = prevBySlot.get(slotId.toUpperCase());
    const text = getText(slotId, fallback || TABLE_TWO_DESC_CARDS_DEFAULTS[slotId] || '', aliases);
    return {
      id: prev?.id || newId('txt-tbl2c'),
      type: 'text',
      role,
      layer: 14,
      slotId,
      placement: {
        x: box.x,
        y: box.y,
        width: box.width,
        height: box.height,
        rotation: 0,
        opacity: 1,
      },
      content: {
        text,
        color: prev?.content?.color || style.color,
        fontSize: style.fontSize,
        fontWeight: style.fontWeight || 600,
        align: style.align || 'center',
        verticalAlign: style.verticalAlign || 'center',
        fontFamily: style.fontFamily || 'Inter, system-ui, sans-serif',
        lineHeight: style.lineHeight || 1.25,
        clipToSlot: style.clipToSlot ?? false,
        letterSpacing: style.letterSpacing || 'normal',
        padding: 0,
        paddingX: 0,
      },
    };
  };

  // 1. Heading & Subtitle
  next.push(
    placeText('HEADING', overlay.heading, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 32,
      fontWeight: 800,
      color: mergedPalette.textDark,
      clipToSlot: false,
      lineHeight: 1.15,
    }, 'heading', TABLE_TWO_DESC_CARDS_DEFAULTS.HEADING, ['TITLE', 'MAIN_TITLE'])
  );

  next.push(
    placeText('SUBTITLE', overlay.subtitle, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 14,
      fontWeight: 400,
      color: mergedPalette.textMuted,
      clipToSlot: false,
      lineHeight: 1.25,
    }, 'subheading', TABLE_TWO_DESC_CARDS_DEFAULTS.SUBTITLE, ['SUBHEADING', 'DESCRIPTION'])
  );

  // 2. Card 1 (Dataset 1)
  next.push(
    placeText('DATASET_1_TITLE', overlay.card1.title, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 18,
      fontWeight: 700,
      color: mergedPalette.textDark,
      clipToSlot: false,
    }, 'heading', TABLE_TWO_DESC_CARDS_DEFAULTS.DATASET_1_TITLE, ['TABLE_1_TITLE', 'DATASET_1'])
  );

  next.push(
    placeText('DATASET_1_SUB', overlay.card1.sub, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 12,
      fontWeight: 500,
      color: mergedPalette.textMuted,
      clipToSlot: false,
    }, 'caption', TABLE_TWO_DESC_CARDS_DEFAULTS.DATASET_1_SUB, ['SUB_1'])
  );

  // Table 1 Column Headers
  const t1ColHeaders = ['A', 'B', 'C'];
  for (let c = 0; c < 3; c += 1) {
    const slotId = `T1_COL_${c + 1}_HEADER`;
    next.push(
      placeText(slotId, overlay.card1.headers[c], {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 700,
        color: mergedPalette.t1HeaderText,
        clipToSlot: false,
      }, 'heading', t1ColHeaders[c], [`COL_${c + 1}_HEADER`])
    );
  }

  // Table 1 Data Rows (3 rows)
  for (let r = 0; r < 3; r += 1) {
    const rowNum = r + 1;
    const rowData = overlay.card1.rows[r];

    next.push(
      placeText(`T1_ROW_${rowNum}_LABEL`, rowData.rowLabel, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 600,
        color: mergedPalette.textDark,
        clipToSlot: false,
      }, 'body', `Row ${rowNum}`, [`ROW_${rowNum}_LABEL`])
    );

    next.push(
      placeText(`T1_CELL_${rowNum}_1`, rowData.cell1, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 500,
        color: mergedPalette.textMuted,
        clipToSlot: false,
      }, 'body', '—', [`CELL_${rowNum}_1`])
    );

    next.push(
      placeText(`T1_CELL_${rowNum}_2`, rowData.cell2, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 500,
        color: mergedPalette.textMuted,
        clipToSlot: false,
      }, 'body', '—', [`CELL_${rowNum}_2`])
    );
  }

  // Description 1 (inside Card 1 - ample height and clipToSlot: false to eliminate any clipping)
  next.push(
    placeText('DESC_1_TITLE', overlay.card1.descTitle, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 15,
      fontWeight: 700,
      color: mergedPalette.textDark,
      clipToSlot: false,
    }, 'heading', TABLE_TWO_DESC_CARDS_DEFAULTS.DESC_1_TITLE, ['CARD_1_TITLE'])
  );

  next.push(
    placeText('DESC_1', overlay.card1.descBody, {
      align: 'left',
      verticalAlign: 'top',
      fontSize: 11.5,
      fontWeight: 400,
      color: mergedPalette.textMuted,
      lineHeight: 1.35,
      clipToSlot: false,
    }, 'body', TABLE_TWO_DESC_CARDS_DEFAULTS.DESC_1, ['BODY_1'])
  );

  // 3. Card 2 (Dataset 2)
  next.push(
    placeText('DATASET_2_TITLE', overlay.card2.title, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 18,
      fontWeight: 700,
      color: mergedPalette.textDark,
      clipToSlot: false,
    }, 'heading', TABLE_TWO_DESC_CARDS_DEFAULTS.DATASET_2_TITLE, ['TABLE_2_TITLE', 'DATASET_2'])
  );

  next.push(
    placeText('DATASET_2_SUB', overlay.card2.sub, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 12,
      fontWeight: 500,
      color: mergedPalette.textMuted,
      clipToSlot: false,
    }, 'caption', TABLE_TWO_DESC_CARDS_DEFAULTS.DATASET_2_SUB, ['SUB_2'])
  );

  // Table 2 Column Headers
  const t2ColHeaders = ['A', 'B', 'C'];
  for (let c = 0; c < 3; c += 1) {
    const slotId = `T2_COL_${c + 1}_HEADER`;
    next.push(
      placeText(slotId, overlay.card2.headers[c], {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 700,
        color: mergedPalette.t2HeaderText,
        clipToSlot: false,
      }, 'heading', t2ColHeaders[c])
    );
  }

  // Table 2 Data Rows (3 rows)
  for (let r = 0; r < 3; r += 1) {
    const rowNum = r + 1;
    const rowData = overlay.card2.rows[r];

    next.push(
      placeText(`T2_ROW_${rowNum}_LABEL`, rowData.rowLabel, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 600,
        color: mergedPalette.textDark,
        clipToSlot: false,
      }, 'body', `Row ${rowNum}`)
    );

    next.push(
      placeText(`T2_CELL_${rowNum}_1`, rowData.cell1, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 500,
        color: mergedPalette.textMuted,
        clipToSlot: false,
      }, 'body', '—')
    );

    next.push(
      placeText(`T2_CELL_${rowNum}_2`, rowData.cell2, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 500,
        color: mergedPalette.textMuted,
        clipToSlot: false,
      }, 'body', '—')
    );
  }

  // Description 2 (inside Card 2 - ample height and clipToSlot: false to eliminate any clipping)
  next.push(
    placeText('DESC_2_TITLE', overlay.card2.descTitle, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 15,
      fontWeight: 700,
      color: mergedPalette.textDark,
      clipToSlot: false,
    }, 'heading', TABLE_TWO_DESC_CARDS_DEFAULTS.DESC_2_TITLE, ['CARD_2_TITLE'])
  );

  next.push(
    placeText('DESC_2', overlay.card2.descBody, {
      align: 'left',
      verticalAlign: 'top',
      fontSize: 11.5,
      fontWeight: 400,
      color: mergedPalette.textMuted,
      lineHeight: 1.35,
      clipToSlot: false,
    }, 'body', TABLE_TWO_DESC_CARDS_DEFAULTS.DESC_2, ['BODY_2'])
  );

  // 4. Vector SVG Chrome (Per-Card Chrome slots for individual selection and real-time color editing)
  const chromeSpecs = tableTwoDescCardsChromeSpecs(mergedPalette);
  const chrome = chromeSpecs.map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase());
    const userFill = prev?.content?.fill;
    const specWithFill = userFill ? { ...spec, color: userFill } : spec;
    const graphic = specToTableTwoDescCardsContent(specWithFill, mergedPalette);
    return {
      id: prev?.id || newId('shp-tbl2c'),
      type: 'graphic',
      layer: spec.layer || 4,
      placement: {
        x: Math.round(spec.x * sx),
        y: Math.round(spec.y * sy),
        width: Math.max(4, Math.round(spec.w * sx)),
        height: Math.max(4, Math.round(spec.h * sy)),
        rotation: 0,
        opacity: 1,
      },
      content: {
        svg: graphic.svg,
        colorMode: graphic.colorMode,
        fill: userFill || graphic.fill || spec.color,
        alt: spec.slotId,
      },
      role: 'decoration',
      slotId: spec.slotId,
    };
  });

  return [...chrome, ...next];
}

module.exports = {
  TABLE_TWO_DESC_CARDS_GEOM,
  TABLE_TWO_DESC_CARDS_PALETTE,
  TABLE_TWO_DESC_CARDS_DEFAULTS,
  isTableTwoDescCardsLayout,
  buildTableTwoDescCardsSvgChrome,
  tableTwoDescCardsChromeSpecs,
  tableTwoDescCardsOverlay,
  tableTwoDescCardsPreviewSvg,
  layoutTableTwoDescCards,
};
