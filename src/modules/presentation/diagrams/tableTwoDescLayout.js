/**
 * Table Two Desc Layout (Backend Diagram Compiler)
 * Layout ID: table_two_desc_v1
 * Features:
 *  - Header (Top Left): Accent gradient bar, Heading ("Compare Datasets") + Subtitle
 *  - Two Side-by-Side Table Cards:
 *    - Left Card (Dataset 1):
 *      - Database storage icon in circle (sky blue)
 *      - Title ("Dataset 1") + Pill badge ("Source A")
 *      - 3-column table (A, B, C) with 3 data rows
 *    - Right Card (Dataset 2):
 *      - Database storage icon in circle (purple)
 *      - Title ("Dataset 2") + Pill badge ("Source B")
 *      - 3-column table (A, B, C) with 3 data rows
 *  - Two Description Cards (Bottom):
 *    - Left Card: Accent blue border, lightbulb icon, "Description 1" + multi-line body
 *    - Right Card: Accent purple border, lightbulb icon, "Description 2" + multi-line body
 *  - Fully theme-responsive and recolorable
 */

const TABLE_TWO_DESC_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Header (Top Left)
  accentX: 44,
  accentY: 28,
  accentW: 36,
  accentH: 4,

  headingX: 44,
  headingY: 38,
  headingW: 800,
  headingH: 34,

  subtitleX: 44,
  subtitleY: 74,
  subtitleW: 800,
  subtitleH: 22,

  // Two Main Cards (Dataset 1 & Dataset 2)
  cardY: 118,
  cardH: 264,
  cardW: 444,
  cardGap: 24,

  card1X: 44,
  card2X: 512,

  // Inside Table Card
  iconOffset: 16,
  iconSize: 36,
  titleXOffset: 60,
  titleYOffset: 16,
  titleH: 36,

  badgeW: 68,
  badgeH: 22,
  badgeYOffset: 22,

  tableXOffset: 16,
  tableYOffset: 64,
  tableW: 412,
  tableHeaderH: 34,
  rowH: 36,
  rows: 3,
  cols: 3,

  // Two Description Cards (Bottom)
  descY: 398,
  descH: 120,
  descW: 444,

  descCard1X: 44,
  descCard2X: 512,

  descIconOffset: 16,
  descTextXOffset: 62,
  descTitleYOffset: 14,
  descTitleH: 24,
  descBodyYOffset: 42,
  descBodyH: 64,
};

const TABLE_TWO_DESC_PALETTE = {
  // Theme 1: Sky / Ocean Blue
  t1Primary: '#0284C7',
  t1BgLight: '#EFF6FF',
  t1IconBg: '#E0F2FE',
  t1BadgeBg: '#E0F2FE',
  t1BadgeText: '#0284C7',
  t1HeaderBg: '#EFF6FF',
  t1HeaderText: '#1E3A8A',
  t1Border: '#BFDBFE',

  // Theme 2: Vibrant Purple
  t2Primary: '#9333EA',
  t2BgLight: '#FAF5FF',
  t2IconBg: '#F3E8FF',
  t2BadgeBg: '#F3E8FF',
  t2BadgeText: '#9333EA',
  t2HeaderBg: '#FAF5FF',
  t2HeaderText: '#581C87',
  t2Border: '#E9D5FF',

  // Shared Neutrals
  cardBg: '#FFFFFF',
  cardBorder: '#E2E8F0',
  gridBorder: '#F1F5F9',
  rowEven: '#FFFFFF',
  rowOdd: '#F8FAFC',
  textDark: '#0F172A',
  textMuted: '#64748B',
  white: '#FFFFFF',
};

const TABLE_TWO_DESC_DEFAULTS = {
  HEADING: 'Compare Datasets',
  SUBTITLE: 'Explore the differences and similarities between the two datasets side by side for a clearer understanding.',

  // Dataset 1
  DATASET_1_TITLE: 'Dataset 1',
  TABLE_1_TITLE: 'Dataset 1',
  DATASET_1_BADGE: 'Source A',
  TAG_1: 'Source A',

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
  DATASET_2_BADGE: 'Source B',
  TAG_2: 'Source B',

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

function isTableTwoDescLayout(layoutId) {
  const s = String(layoutId || '').toLowerCase();
  return (
    s === 'table_two_desc_v1' ||
    s === 'table_two_desc' ||
    s === 'table_dual'
  );
}

/**
 * Builds vector SVG Chrome with cards, headers, borders, and crisp SVG icons
 */
function buildTableTwoDescSvgChrome(palette = TABLE_TWO_DESC_PALETTE) {
  const g = TABLE_TWO_DESC_GEOM;
  const t1Color = palette.t1Primary || TABLE_TWO_DESC_PALETTE.t1Primary;
  const t2Color = palette.t2Primary || TABLE_TWO_DESC_PALETTE.t2Primary;
  const t1IconBg = palette.t1IconBg || TABLE_TWO_DESC_PALETTE.t1IconBg;
  const t2IconBg = palette.t2IconBg || TABLE_TWO_DESC_PALETTE.t2IconBg;
  const t1HeaderBg = palette.t1HeaderBg || TABLE_TWO_DESC_PALETTE.t1HeaderBg;
  const t2HeaderBg = palette.t2HeaderBg || TABLE_TWO_DESC_PALETTE.t2HeaderBg;

  // Outline Database stack icon
  const dbIconSvg = (color) => `
    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <ellipse cx="12" cy="5" rx="9" ry="3"/>
      <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
      <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
    </svg>
  `;

  // Outline Lightbulb icon
  const bulbIconSvg = (color) => `
    <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M9 18h6"/>
      <path d="M10 22h4"/>
      <path d="M15.09 14c.18-.98.65-1.74 1.41-2.5A4.65 4.65 0 0 0 18 8 6 6 0 0 0 6 8c0 1 .23 2.23 1.5 3.5A4.61 4.61 0 0 1 8.91 14"/>
    </svg>
  `;

  const svgParts = [];

  // Top-left accent bar
  svgParts.push(`
    <defs>
      <linearGradient id="tbl2DescAccent" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="${t1Color}" />
        <stop offset="100%" stop-color="${t2Color}" />
      </linearGradient>
      <linearGradient id="cornerWave" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="#38BDF8" stop-opacity="0.12" />
        <stop offset="100%" stop-color="#818CF8" stop-opacity="0.04" />
      </linearGradient>
    </defs>
    <!-- Subtle aesthetic corner waves in background -->
    <path d="M850 0 C920 10, 970 50, 1000 130 L1000 0 Z" fill="url(#cornerWave)" />
    <path d="M430 560 C460 510, 480 490, 500 480 L444 560 Z" fill="#E0F2FE" opacity="0.4" />
    <path d="M920 560 C950 510, 980 490, 1000 480 L1000 560 Z" fill="#F3E8FF" opacity="0.4" />

    <!-- Accent pill -->
    <rect x="${g.accentX}" y="${g.accentY}" width="${g.accentW}" height="${g.accentH}" rx="2" fill="url(#tbl2DescAccent)" />
  `);

  // Function to build one of the two main table cards
  const buildTableCardSvg = (cardX, isT1) => {
    const mainColor = isT1 ? t1Color : t2Color;
    const iconBg = isT1 ? t1IconBg : t2IconBg;
    const headerBg = isT1 ? t1HeaderBg : t2HeaderBg;
    const badgeBg = isT1 ? palette.t1BadgeBg : palette.t2BadgeBg;

    const iconX = cardX + g.iconOffset;
    const iconY = g.cardY + g.iconOffset;
    const badgeX = cardX + g.cardW - g.iconOffset - g.badgeW;
    const badgeY = g.cardY + g.badgeYOffset;

    const tableX = cardX + g.tableXOffset;
    const tableY = g.cardY + g.tableYOffset;
    const colW = g.tableW / g.cols;

    let innerTable = `
      <!-- Table Header Bar -->
      <rect x="${tableX}" y="${tableY}" width="${g.tableW}" height="${g.tableHeaderH}" rx="8" fill="${headerBg}" />
    `;

    // Table Row dividers
    for (let r = 0; r < g.rows; r += 1) {
      const rowY = tableY + g.tableHeaderH + r * g.rowH;
      const isEven = r % 2 === 0;
      const rowBg = isEven ? palette.rowEven : palette.rowOdd;

      innerTable += `
        <!-- Row ${r + 1} background -->
        <rect x="${tableX}" y="${rowY}" width="${g.tableW}" height="${g.rowH}" fill="${rowBg}" />
        <!-- Bottom divider line -->
        <line x1="${tableX}" y1="${rowY + g.rowH}" x2="${tableX + g.tableW}" y2="${rowY + g.rowH}" stroke="${palette.gridBorder}" stroke-width="1" />
      `;
    }

    // Vertical column divider lines
    for (let c = 1; c < g.cols; c += 1) {
      const divX = tableX + c * colW;
      innerTable += `
        <line x1="${divX}" y1="${tableY}" x2="${divX}" y2="${tableY + g.tableHeaderH + g.rows * g.rowH}" stroke="${palette.gridBorder}" stroke-width="1" />
      `;
    }

    return `
      <!-- Card Container -->
      <rect x="${cardX}" y="${g.cardY}" width="${g.cardW}" height="${g.cardH}" rx="14" fill="${palette.cardBg}" stroke="${palette.cardBorder}" stroke-width="1" />

      <!-- Circle Icon -->
      <circle cx="${iconX + g.iconSize / 2}" cy="${iconY + g.iconSize / 2}" r="${g.iconSize / 2}" fill="${iconBg}" />
      <g transform="translate(${iconX + (g.iconSize - 20) / 2}, ${iconY + (g.iconSize - 20) / 2})">
        ${dbIconSvg(mainColor)}
      </g>

      <!-- Pill Badge Background -->
      <rect x="${badgeX}" y="${badgeY}" width="${g.badgeW}" height="${g.badgeH}" rx="11" fill="${badgeBg}" />

      <!-- Inner Table Grid -->
      <g>
        ${innerTable}
      </g>
    `;
  };

  // Function to build one of the two bottom description cards
  const buildDescCardSvg = (cardX, isT1) => {
    const mainColor = isT1 ? t1Color : t2Color;
    const iconBg = isT1 ? t1IconBg : t2IconBg;

    const iconX = cardX + g.descIconOffset;
    const iconY = g.descY + 20;

    return `
      <!-- Desc Card Container -->
      <rect x="${cardX}" y="${g.descY}" width="${g.descW}" height="${g.descH}" rx="12" fill="${palette.cardBg}" stroke="${palette.cardBorder}" stroke-width="1" />

      <!-- Left Accent Border Strip -->
      <rect x="${cardX}" y="${g.descY + 4}" width="5" height="${g.descH - 8}" rx="2.5" fill="${mainColor}" />

      <!-- Circle Icon with Lightbulb -->
      <circle cx="${iconX + g.iconSize / 2}" cy="${iconY + g.iconSize / 2}" r="${g.iconSize / 2}" fill="${iconBg}" />
      <g transform="translate(${iconX + (g.iconSize - 20) / 2}, ${iconY + (g.iconSize - 20) / 2})">
        ${bulbIconSvg(mainColor)}
      </g>
    `;
  };

  // Add Card 1 & Card 2
  svgParts.push(buildTableCardSvg(g.card1X, true));
  svgParts.push(buildTableCardSvg(g.card2X, false));

  // Add Desc 1 & Desc 2
  svgParts.push(buildDescCardSvg(g.descCard1X, true));
  svgParts.push(buildDescCardSvg(g.descCard2X, false));

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" fill="none">${svgParts.join('\n')}</svg>`;
}

function tableTwoDescChromeSpecs() {
  const g = TABLE_TWO_DESC_GEOM;
  return [
    {
      slotId: 'TABLE_TWO_DESC_CHROME',
      x: 0,
      y: 0,
      w: g.viewW,
      h: g.viewH,
      layer: 4,
    },
  ];
}

function tableTwoDescOverlay(canvasW, canvasH) {
  const g = TABLE_TWO_DESC_GEOM;
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

  const buildCardOverlay = (cardX) => {
    const title = {
      x: Math.round((cardX + g.titleXOffset) * sx),
      y: Math.round((g.cardY + g.titleYOffset) * sy),
      width: Math.round((g.cardW - g.titleXOffset - g.badgeW - 24) * sx),
      height: Math.round(g.titleH * sy),
    };

    const badge = {
      x: Math.round((cardX + g.cardW - g.iconOffset - g.badgeW) * sx),
      y: Math.round((g.cardY + g.badgeYOffset) * sy),
      width: Math.round(g.badgeW * sx),
      height: Math.round(g.badgeH * sy),
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

    // 3 Rows x 3 Cols (Col 1 is label, Col 2 & 3 are data cells)
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

    return { title, badge, headers, rows };
  };

  const buildDescOverlay = (cardX) => {
    const title = {
      x: Math.round((cardX + g.descTextXOffset) * sx),
      y: Math.round((g.descY + g.descTitleYOffset) * sy),
      width: Math.round((g.descW - g.descTextXOffset - 16) * sx),
      height: Math.round(g.descTitleH * sy),
    };

    const body = {
      x: Math.round((cardX + g.descTextXOffset) * sx),
      y: Math.round((g.descY + g.descBodyYOffset) * sy),
      width: Math.round((g.descW - g.descTextXOffset - 16) * sx),
      height: Math.round(g.descBodyH * sy),
    };

    return { title, body };
  };

  return {
    heading,
    subtitle,
    card1: buildCardOverlay(g.card1X),
    card2: buildCardOverlay(g.card2X),
    desc1: buildDescOverlay(g.descCard1X),
    desc2: buildDescOverlay(g.descCard2X),
  };
}

function specToTableTwoDescContent(spec, palette) {
  return {
    svg: buildTableTwoDescSvgChrome(palette),
    colorMode: 'recolorable',
    fill: palette?.primary || TABLE_TWO_DESC_PALETTE.t1Primary,
  };
}

function tableTwoDescPreviewSvg() {
  return buildTableTwoDescSvgChrome(TABLE_TWO_DESC_PALETTE);
}

/**
 * Main Layout Compiler for Table Two Desc
 */
function layoutTableTwoDesc(elements, schema, palette = {}, canvas = {}) {
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const sx = canvasW / TABLE_TWO_DESC_GEOM.viewW;
  const sy = canvasH / TABLE_TWO_DESC_GEOM.viewH;

  const mergedPalette = {
    ...TABLE_TWO_DESC_PALETTE,
    ...(palette?.primary ? {
      t1Primary: palette.primary,
      t1IconBg: palette.primaryLight || '#E0F2FE',
      t1BadgeBg: palette.primaryLight || '#E0F2FE',
      t1BadgeText: palette.primary,
      t1HeaderBg: palette.primaryLight || '#EFF6FF',
      t1HeaderText: palette.primaryDark || '#1E3A8A',
    } : {}),
    ...(palette?.secondary ? {
      t2Primary: palette.secondary,
      t2IconBg: palette.secondaryLight || '#F3E8FF',
      t2BadgeBg: palette.secondaryLight || '#F3E8FF',
      t2BadgeText: palette.secondary,
      t2HeaderBg: palette.secondaryLight || '#FAF5FF',
      t2HeaderText: palette.secondaryDark || '#581C87',
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

  const overlay = tableTwoDescOverlay(canvasW, canvasH);
  const next = [];

  const placeText = (slotId, box, style, role = 'body', fallback = '', aliases = []) => {
    const prev = prevBySlot.get(slotId.toUpperCase());
    const text = getText(slotId, fallback || TABLE_TWO_DESC_DEFAULTS[slotId] || '', aliases);
    return {
      id: prev?.id || newId('txt-tbl2'),
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
        color: style.color,
        fontSize: style.fontSize,
        fontWeight: style.fontWeight || 600,
        align: style.align || 'center',
        verticalAlign: style.verticalAlign || 'center',
        fontFamily: style.fontFamily || 'Inter, system-ui, sans-serif',
        lineHeight: style.lineHeight || 1.2,
        clipToSlot: style.clipToSlot ?? true,
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
      clipToSlot: true,
      lineHeight: 1.15,
    }, 'heading', TABLE_TWO_DESC_DEFAULTS.HEADING, ['TITLE', 'MAIN_TITLE'])
  );

  next.push(
    placeText('SUBTITLE', overlay.subtitle, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 14,
      fontWeight: 400,
      color: mergedPalette.textMuted,
      clipToSlot: true,
      lineHeight: 1.25,
    }, 'subheading', TABLE_TWO_DESC_DEFAULTS.SUBTITLE, ['SUBHEADING', 'DESCRIPTION'])
  );

  // 2. Card 1 (Dataset 1)
  next.push(
    placeText('DATASET_1_TITLE', overlay.card1.title, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 18,
      fontWeight: 700,
      color: mergedPalette.textDark,
      clipToSlot: true,
    }, 'heading', TABLE_TWO_DESC_DEFAULTS.DATASET_1_TITLE, ['TABLE_1_TITLE', 'DATASET_1'])
  );

  next.push(
    placeText('DATASET_1_BADGE', overlay.card1.badge, {
      align: 'center',
      verticalAlign: 'center',
      fontSize: 11,
      fontWeight: 600,
      color: mergedPalette.t1BadgeText,
      clipToSlot: true,
    }, 'badge', TABLE_TWO_DESC_DEFAULTS.DATASET_1_BADGE, ['TAG_1', 'SOURCE_1'])
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
        clipToSlot: true,
      }, 'heading', t1ColHeaders[c], [`COL_${c + 1}_HEADER`])
    );
  }

  // Table 1 Data Rows (3 rows)
  for (let r = 0; r < 3; r += 1) {
    const rowNum = r + 1;
    const rowData = overlay.card1.rows[r];

    // Row label (Row 1, Row 2, Row 3)
    next.push(
      placeText(`T1_ROW_${rowNum}_LABEL`, rowData.rowLabel, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 600,
        color: mergedPalette.textDark,
        clipToSlot: true,
      }, 'body', `Row ${rowNum}`, [`ROW_${rowNum}_LABEL`])
    );

    // Cell 1
    next.push(
      placeText(`T1_CELL_${rowNum}_1`, rowData.cell1, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 500,
        color: mergedPalette.textMuted,
        clipToSlot: true,
      }, 'body', '—', [`CELL_${rowNum}_1`])
    );

    // Cell 2
    next.push(
      placeText(`T1_CELL_${rowNum}_2`, rowData.cell2, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 500,
        color: mergedPalette.textMuted,
        clipToSlot: true,
      }, 'body', '—', [`CELL_${rowNum}_2`])
    );
  }

  // 3. Card 2 (Dataset 2)
  next.push(
    placeText('DATASET_2_TITLE', overlay.card2.title, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 18,
      fontWeight: 700,
      color: mergedPalette.textDark,
      clipToSlot: true,
    }, 'heading', TABLE_TWO_DESC_DEFAULTS.DATASET_2_TITLE, ['TABLE_2_TITLE', 'DATASET_2'])
  );

  next.push(
    placeText('DATASET_2_BADGE', overlay.card2.badge, {
      align: 'center',
      verticalAlign: 'center',
      fontSize: 11,
      fontWeight: 600,
      color: mergedPalette.t2BadgeText,
      clipToSlot: true,
    }, 'badge', TABLE_TWO_DESC_DEFAULTS.DATASET_2_BADGE, ['TAG_2', 'SOURCE_2'])
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
        clipToSlot: true,
      }, 'heading', t2ColHeaders[c])
    );
  }

  // Table 2 Data Rows (3 rows)
  for (let r = 0; r < 3; r += 1) {
    const rowNum = r + 1;
    const rowData = overlay.card2.rows[r];

    // Row label
    next.push(
      placeText(`T2_ROW_${rowNum}_LABEL`, rowData.rowLabel, {
        align: 'left',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 600,
        color: mergedPalette.textDark,
        clipToSlot: true,
      }, 'body', `Row ${rowNum}`)
    );

    // Cell 1
    next.push(
      placeText(`T2_CELL_${rowNum}_1`, rowData.cell1, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 500,
        color: mergedPalette.textMuted,
        clipToSlot: true,
      }, 'body', '—')
    );

    // Cell 2
    next.push(
      placeText(`T2_CELL_${rowNum}_2`, rowData.cell2, {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 500,
        color: mergedPalette.textMuted,
        clipToSlot: true,
      }, 'body', '—')
    );
  }

  // 4. Description 1 (Bottom Left)
  next.push(
    placeText('DESC_1_TITLE', overlay.desc1.title, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 16,
      fontWeight: 700,
      color: mergedPalette.textDark,
      clipToSlot: true,
    }, 'heading', TABLE_TWO_DESC_DEFAULTS.DESC_1_TITLE, ['CARD_1_TITLE'])
  );

  next.push(
    placeText('DESC_1', overlay.desc1.body, {
      align: 'left',
      verticalAlign: 'top',
      fontSize: 12.5,
      fontWeight: 400,
      color: mergedPalette.textMuted,
      lineHeight: 1.4,
      clipToSlot: true,
    }, 'body', TABLE_TWO_DESC_DEFAULTS.DESC_1, ['BODY_1'])
  );

  // 5. Description 2 (Bottom Right)
  next.push(
    placeText('DESC_2_TITLE', overlay.desc2.title, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 16,
      fontWeight: 700,
      color: mergedPalette.textDark,
      clipToSlot: true,
    }, 'heading', TABLE_TWO_DESC_DEFAULTS.DESC_2_TITLE, ['CARD_2_TITLE'])
  );

  next.push(
    placeText('DESC_2', overlay.desc2.body, {
      align: 'left',
      verticalAlign: 'top',
      fontSize: 12.5,
      fontWeight: 400,
      color: mergedPalette.textMuted,
      lineHeight: 1.4,
      clipToSlot: true,
    }, 'body', TABLE_TWO_DESC_DEFAULTS.DESC_2, ['BODY_2'])
  );

  // 6. Vector SVG Chrome (Cards, Icons, Headers, Dividers)
  const chrome = tableTwoDescChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase());
    const graphic = specToTableTwoDescContent(spec, mergedPalette);
    return {
      id: prev?.id || newId('shp-tbl2desc'),
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
        fill: graphic.fill,
        alt: spec.slotId,
      },
      role: 'decoration',
      slotId: spec.slotId,
    };
  });

  return [...chrome, ...next];
}

module.exports = {
  TABLE_TWO_DESC_GEOM,
  TABLE_TWO_DESC_PALETTE,
  TABLE_TWO_DESC_DEFAULTS,
  isTableTwoDescLayout,
  buildTableTwoDescSvgChrome,
  tableTwoDescChromeSpecs,
  tableTwoDescOverlay,
  tableTwoDescPreviewSvg,
  layoutTableTwoDesc,
};
