/**
 * Table with Description Layout (Backend CommonJS)
 * Layout ID: table_with_description_v1
 * Features:
 *  - Header: Left title + vertical accent divider bar + multi-line paragraph description
 *  - Left column: 6 row pills with 3D bevel & layered backplate, each featuring a distinct circular vector icon badge
 *  - Right table: 4 columns with rounded top header tabs and 6 alternating shaded data rows
 *  - Theme responsive: Professional corporate Navy/Slate default, dynamically recolorable via theme palette
 */

const TABLE_WITH_DESC_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Header geometry
  headingX: 36,
  headingY: 18,
  headingW: 300,
  headingH: 58,

  dividerX: 346,
  dividerY: 20,
  dividerW: 3,
  dividerH: 54,

  descX: 362,
  descY: 18,
  descW: 602,
  descH: 58,

  // Table geometry
  tableY: 96,
  tableH: 434,

  // Left row badges column
  leftColX: 36,
  leftBackdropW: 216,
  rowPillX: 80,
  rowPillW: 172,
  rowPillH: 52,
  iconBadgeX: 42,
  iconBadgeRadius: 19,

  // Data table columns
  dataStartX: 266,
  colW: 168,
  colGap: 6,
  cols: 4,

  headerH: 44,
  rowH: 52,
  rowGap: 7,
  rows: 6,
};

const TABLE_WITH_DESC_PALETTE = {
  primary: '#1E3A8A', // Professional Deep Navy
  primaryDark: '#0F172A', // Slate / Dark Navy
  primaryLight: '#3B82F6', // Corporate Blue Accent
  backdrop: '#F1F5F9', // Subtle Backing Container
  pillBevel: '#172554', // Pill 3D shadow/edge
  pillBg: '#1E3A8A', // Row Pill Background

  // Distinct icon badge colors (Professional Corporate Spectrum)
  iconBgs: [
    '#2563EB', // Row 1: Corporate Blue (Briefcase)
    '#EA580C', // Row 2: Warm Amber/Orange (ID Card)
    '#D97706', // Row 3: Golden Sun (Money Bag)
    '#0D9488', // Row 4: Deep Teal (Checklist)
    '#7C3AED', // Row 5: Vibrant Violet (Megaphone)
    '#F59E0B', // Row 6: Amber (User Badge)
  ],

  // Table cell fills
  colHeaderBg: '#1E3A8A',
  cellEven: '#FFFFFF',
  cellOdd: '#F8FAFC',
  cellBorder: '#E2E8F0',

  textDark: '#0F172A',
  textMuted: '#64748B',
  white: '#FFFFFF',
};

const TABLE_WITH_DESC_DEFAULTS = {
  HEADING: 'Table Template',
  BODY: 'This slide presents a set of customizable table templates designed for clear and structured data presentation. Each row is visually supported by intuitive icons, making it easy to categorize and compare information across different business functions or metrics.',
  DESCRIPTION: 'This slide presents a set of customizable table templates designed for clear and structured data presentation. Each row is visually supported by intuitive icons, making it easy to categorize and compare information across different business functions or metrics.',

  COL_1_HEADER: 'Add Text Here',
  COL_2_HEADER: 'Add Text Here',
  COL_3_HEADER: 'Add Text Here',
  COL_4_HEADER: 'Add Text Here',

  ROW_1_LABEL: 'Add Text Here',
  ROW_2_LABEL: 'Add Text Here',
  ROW_3_LABEL: 'Add Text Here',
  ROW_4_LABEL: 'Add Text Here',
  ROW_5_LABEL: 'Add Text Here',
  ROW_6_LABEL: 'Add Text Here',

  CELL_1_1: 'Lorem ipsum dolor\nsit amet',
  CELL_1_2: 'Lorem ipsum dolor\nsit amet',
  CELL_1_3: 'Lorem ipsum dolor\nsit amet',
  CELL_1_4: 'Lorem ipsum dolor\nsit amet',

  CELL_2_1: 'Lorem ipsum dolor\nsit amet',
  CELL_2_2: 'Lorem ipsum dolor\nsit amet',
  CELL_2_3: 'Lorem ipsum dolor\nsit amet',
  CELL_2_4: 'Lorem ipsum dolor\nsit amet',

  CELL_3_1: 'Lorem ipsum dolor\nsit amet',
  CELL_3_2: 'Lorem ipsum dolor\nsit amet',
  CELL_3_3: 'Lorem ipsum dolor\nsit amet',
  CELL_3_4: 'Lorem ipsum dolor\nsit amet',

  CELL_4_1: 'Lorem ipsum dolor\nsit amet',
  CELL_4_2: 'Lorem ipsum dolor\nsit amet',
  CELL_4_3: 'Lorem ipsum dolor\nsit amet',
  CELL_4_4: 'Lorem ipsum dolor\nsit amet',

  CELL_5_1: 'Lorem ipsum dolor\nsit amet',
  CELL_5_2: 'Lorem ipsum dolor\nsit amet',
  CELL_5_3: 'Lorem ipsum dolor\nsit amet',
  CELL_5_4: 'Lorem ipsum dolor\nsit amet',

  CELL_6_1: 'Lorem ipsum dolor\nsit amet',
  CELL_6_2: 'Lorem ipsum dolor\nsit amet',
  CELL_6_3: 'Lorem ipsum dolor\nsit amet',
  CELL_6_4: 'Lorem ipsum dolor\nsit amet',
};

function isTableWithDescriptionLayout(layoutId) {
  const s = String(layoutId || '').toLowerCase();
  return s === 'table_with_description_v1' || s === 'table_with_desc';
}

function isTableWithDescriptionTextSlot(slotId) {
  const s = String(slotId || '').toUpperCase();
  return (
    s === 'HEADING' ||
    s === 'BODY' ||
    s === 'DESCRIPTION' ||
    /^COL_\d+_HEADER$/i.test(s) ||
    /^ROW_\d+_LABEL$/i.test(s) ||
    /^CELL_\d+_\d+$/i.test(s)
  );
}

/**
 * 6 High-clarity SVG vector icons for the left row badges (24x24 coordinate base)
 */
const ICON_SVGS = [
  // 1. Briefcase
  `<svg viewBox="0 0 24 24" width="22" height="22"><path fill="#FFFFFF" d="M10 3.5a1.5 1.5 0 0 0-1.5 1.5V6H5a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2v5a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-5a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-3.5V5A1.5 1.5 0 0 0 14 3.5h-4zm.5 2.5v-.5a.5.5 0 0 1 .5-.5h4a.5.5 0 0 1 .5.5V6h-5zM5 8h14v2.5H5V8zm2 5h10v5H7v-5z"/></svg>`,
  // 2. ID Card / Badge
  `<svg viewBox="0 0 24 24" width="22" height="22"><path fill="#FFFFFF" d="M3 5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5zm4 2.5a2 2 0 1 0 0 4 2 2 0 0 0 0-4zm6 1h5v1.8h-5V8.5zm0 3.5h5v1.8h-5V12zM5.5 16.5c0-1.4 1.8-2.2 3.5-2.2s3.5.8 3.5 2.2V17h-7v-.5zm8-1h4.5v1.8h-4.5v-1.8z"/></svg>`,
  // 3. Money Sack
  `<svg viewBox="0 0 24 24" width="22" height="22"><path fill="#FFFFFF" d="M12 2.5a3 3 0 0 0-2.8 2H6.5A2.5 2.5 0 0 0 4 7v1c0 5 3 9 8 9s8-4 8-9V7a2.5 2.5 0 0 0-2.5-2.5h-2.7A3 3 0 0 0 12 2.5zm0 6c1.6 0 2.8.8 2.8 1.8s-1.2 1.8-2.8 1.8c-.6 0-1-.3-1-.8v-.1c0-.4.4-.8 1-.8s1 .4 1 .8a.8.8 0 0 0 1.6 0c0-1.4-1.3-2.2-2.6-2.2s-2.6.8-2.6 2.2a2.6 2.6 0 0 0 2.6 2.6c1.6 0 2.8.8 2.8 1.8s-1.2 1.8-2.8 1.8-2.8-.8-2.8-1.8a.8.8 0 1 0-1.6 0c0 1.4 1.3 2.2 2.6 2.2v.8h1.6v-.8c2-.2 3.4-1.2 3.4-2.6s-1.4-2.6-3.4-2.6c-.6 0-1-.3-1-.8s.4-.8 1-.8z"/></svg>`,
  // 4. Checklist / Document
  `<svg viewBox="0 0 24 24" width="22" height="22"><path fill="#FFFFFF" d="M6 3h8.5l4.5 4.5V20a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zm7 1.5V8h3.5L13 4.5zM7.5 10.5v1.8h9v-1.8h-9zm0 3.8v1.8h9v-1.8h-9zm0 3.8v1.8h6v-1.8h-6z"/></svg>`,
  // 5. Megaphone
  `<svg viewBox="0 0 24 24" width="22" height="22"><path fill="#FFFFFF" d="M18 4.2a1 1 0 0 1 1.6.8v10a1 1 0 0 1-1.6.8L13.5 12.5H9a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h4.5l4.5-3.3zM7 14v4a2 2 0 0 0 2 2h1a1 1 0 0 0 1-1v-5H7zm13-5a4.5 4.5 0 0 1 0 4v-1a2.5 2.5 0 0 0 0-2v-1z"/></svg>`,
  // 6. Contact / User Badge
  `<svg viewBox="0 0 24 24" width="22" height="22"><path fill="#FFFFFF" d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm4.5 3a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5zm-3 8.2c0-1.4 1.8-2.2 3.5-2.2s3.5.8 3.5 2.2V16H5.5v-.8zm7.5-6.2h6v1.8h-6V9zm0 3.5h6v1.8h-6v-1.8zm0 3.5h4.5v1.8H13V16z"/></svg>`,
];

function buildTableWithDescriptionSvgChrome(palette = TABLE_WITH_DESC_PALETTE) {
  const g = TABLE_WITH_DESC_GEOM;
  const primary = palette.primary || TABLE_WITH_DESC_PALETTE.primary;
  const primaryDark = palette.primaryDark || TABLE_WITH_DESC_PALETTE.primaryDark;
  const backdrop = palette.backdrop || TABLE_WITH_DESC_PALETTE.backdrop;

  const svgParts = [];

  // 1. Top vertical accent divider bar
  svgParts.push(`
    <rect x="${g.dividerX}" y="${g.dividerY}" width="${g.dividerW}" height="${g.dividerH}" rx="1.5" fill="${primary}" />
  `);

  // 2. Left Row Column Background Plate
  const leftBackplateY = g.tableY + 52;
  const leftBackplateH = g.rows * (g.rowH + g.rowGap) - g.rowGap + 10;
  svgParts.push(`
    <!-- Left Column Backdrop -->
    <rect x="${g.leftColX}" y="${leftBackplateY - 5}" width="${g.leftBackdropW + 20}" height="${leftBackplateH}" rx="16" fill="${backdrop}" />
  `);

  // 3. 6 Left Row Badges (Pills with circular icon badges)
  for (let r = 0; r < g.rows; r += 1) {
    const rowY = g.tableY + 52 + r * (g.rowH + g.rowGap);
    const iconBg = palette.iconBgs?.[r] || TABLE_WITH_DESC_PALETTE.iconBgs[r % TABLE_WITH_DESC_PALETTE.iconBgs.length];
    const iconSvg = ICON_SVGS[r % ICON_SVGS.length];

    svgParts.push(`
      <g id="row-pill-${r + 1}">
        <rect x="${g.rowPillX}" y="${rowY + 2}" width="${g.rowPillW}" height="${g.rowPillH}" rx="12" fill="${primaryDark}" opacity="0.35" />
        <rect x="${g.rowPillX}" y="${rowY}" width="${g.rowPillW}" height="${g.rowPillH}" rx="12" fill="${primary}" />
        <circle cx="${g.iconBadgeX + g.iconBadgeRadius}" cy="${rowY + g.rowPillH / 2}" r="${g.iconBadgeRadius + 3}" fill="#FFFFFF" />
        <circle cx="${g.iconBadgeX + g.iconBadgeRadius}" cy="${rowY + g.rowPillH / 2}" r="${g.iconBadgeRadius}" fill="${iconBg}" />
        <g transform="translate(${g.iconBadgeX + g.iconBadgeRadius - 11}, ${rowY + g.rowPillH / 2 - 11})">
          ${iconSvg}
        </g>
      </g>
    `);
  }

  // 4. Data Columns Header Tabs
  for (let c = 0; c < g.cols; c += 1) {
    const colX = g.dataStartX + c * (g.colW + g.colGap);
    svgParts.push(`
      <g id="col-header-${c + 1}">
        <rect x="${colX}" y="${g.tableY}" width="${g.colW}" height="${g.headerH}" rx="8" fill="${primary}" />
      </g>
    `);
  }

  // 5. Data Body Rows Grid (24 Cells)
  for (let r = 0; r < g.rows; r += 1) {
    const rowY = g.tableY + 52 + r * (g.rowH + g.rowGap);
    const isEven = r % 2 === 0;
    const cellBg = isEven ? TABLE_WITH_DESC_PALETTE.cellEven : TABLE_WITH_DESC_PALETTE.cellOdd;

    for (let c = 0; c < g.cols; c += 1) {
      const colX = g.dataStartX + c * (g.colW + g.colGap);
      svgParts.push(`
        <rect x="${colX}" y="${rowY}" width="${g.colW}" height="${g.rowH}" rx="6" fill="${cellBg}" stroke="${TABLE_WITH_DESC_PALETTE.cellBorder}" stroke-width="1" />
      `);
    }
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" fill="none">${svgParts.join('\n')}</svg>`;
}

function tableWithDescriptionChromeSpecs() {
  const g = TABLE_WITH_DESC_GEOM;
  return [
    {
      slotId: 'TABLE_WITH_DESC_CHROME',
      x: 0,
      y: 0,
      w: g.viewW,
      h: g.viewH,
      layer: 4,
    },
  ];
}

function tableWithDescriptionOverlay(canvasW, canvasH) {
  const g = TABLE_WITH_DESC_GEOM;
  const sx = canvasW / g.viewW;
  const sy = canvasH / g.viewH;

  const heading = {
    x: Math.round(g.headingX * sx),
    y: Math.round(g.headingY * sy),
    width: Math.round(g.headingW * sx),
    height: Math.round(g.headingH * sy),
  };

  const description = {
    x: Math.round(g.descX * sx),
    y: Math.round(g.descY * sy),
    width: Math.round(g.descW * sx),
    height: Math.round(g.descH * sy),
  };

  const colHeaders = [];
  for (let c = 0; c < g.cols; c += 1) {
    const colX = g.dataStartX + c * (g.colW + g.colGap);
    colHeaders.push({
      x: Math.round((colX + 4) * sx),
      y: Math.round((g.tableY + 3) * sy),
      width: Math.round((g.colW - 8) * sx),
      height: Math.round((g.headerH - 6) * sy),
    });
  }

  const rowLabels = [];
  for (let r = 0; r < g.rows; r += 1) {
    const rowY = g.tableY + 52 + r * (g.rowH + g.rowGap);
    rowLabels.push({
      x: Math.round((g.rowPillX + 10) * sx),
      y: Math.round((rowY + 4) * sy),
      width: Math.round((g.rowPillW - 20) * sx),
      height: Math.round((g.rowPillH - 8) * sy),
    });
  }

  const cells = [];
  for (let r = 0; r < g.rows; r += 1) {
    const rowCells = [];
    const rowY = g.tableY + 52 + r * (g.rowH + g.rowGap);
    for (let c = 0; c < g.cols; c += 1) {
      const colX = g.dataStartX + c * (g.colW + g.colGap);
      rowCells.push({
        x: Math.round((colX + 4) * sx),
        y: Math.round((rowY + 3) * sy),
        width: Math.round((g.colW - 8) * sx),
        height: Math.round((g.rowH - 6) * sy),
      });
    }
    cells.push(rowCells);
  }

  return {
    heading,
    description,
    colHeaders,
    rowLabels,
    cells,
  };
}

function specToTableWithDescriptionContent(spec, palette) {
  return {
    svg: buildTableWithDescriptionSvgChrome(palette),
    colorMode: 'recolorable',
    fill: palette?.primary || TABLE_WITH_DESC_PALETTE.primary,
  };
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`;
}

function layoutTableWithDescriptionElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const sx = canvasW / TABLE_WITH_DESC_GEOM.viewW;
  const sy = canvasH / TABLE_WITH_DESC_GEOM.viewH;

  const mergedPalette = {
    ...TABLE_WITH_DESC_PALETTE,
    ...(palette?.primary ? { primary: palette.primary, colHeaderBg: palette.primary, pillBg: palette.primary } : {}),
    ...(palette?.text ? { textDark: palette.text } : {}),
    ...(palette?.muted ? { textMuted: palette.muted } : {}),
  };

  const prevBySlot = new Map();
  for (const el of elements || []) {
    const sid = String(el.slotId || el.id || '').toUpperCase();
    if (sid) prevBySlot.set(sid, el);
  }

  const getText = (slotId, fallback) => {
    const match = prevBySlot.get(slotId.toUpperCase());
    if (!match?.content) return fallback;
    const text = typeof match.content === 'string' ? match.content : match.content.text || match.content.body;
    return (text !== undefined && text !== null && String(text).trim() !== '') ? String(text) : fallback;
  };

  const overlay = tableWithDescriptionOverlay(canvasW, canvasH);
  const next = [];

  const placeText = (slotId, box, style, role = 'body') => {
    const prev = prevBySlot.get(slotId.toUpperCase());
    const text = getText(slotId, TABLE_WITH_DESC_DEFAULTS[slotId] || '');
    return {
      id: prev?.id || newId('txt-tbldesc'),
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
        lineHeight: style.lineHeight || 1.25,
        clipToSlot: style.clipToSlot ?? true,
        letterSpacing: style.letterSpacing || 'normal',
        padding: 0,
        paddingX: 0,
      },
    };
  };

  // 1. Heading (fits neatly on 1 line)
  next.push(
    placeText('HEADING', overlay.heading, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 24,
      fontWeight: 800,
      color: mergedPalette.textDark,
      clipToSlot: true,
      lineHeight: 1.15,
    }, 'heading')
  );

  // 2. Description
  const descText = getText('DESCRIPTION', getText('BODY', TABLE_WITH_DESC_DEFAULTS.DESCRIPTION));
  const prevDesc = prevBySlot.get('DESCRIPTION') || prevBySlot.get('BODY');
  next.push({
    id: prevDesc?.id || newId('txt-tbldesc'),
    type: 'text',
    role: 'body',
    layer: 14,
    slotId: 'DESCRIPTION',
    placement: {
      x: overlay.description.x,
      y: overlay.description.y,
      width: overlay.description.width,
      height: overlay.description.height,
      rotation: 0,
      opacity: 1,
    },
    content: {
      text: descText,
      color: mergedPalette.textMuted,
      fontSize: 11.5,
      fontWeight: 500,
      align: 'left',
      verticalAlign: 'center',
      fontFamily: 'Inter, system-ui, sans-serif',
      lineHeight: 1.35,
      clipToSlot: true,
      padding: 0,
      paddingX: 0,
    },
  });

  // 3. 4 Column Headers
  for (let c = 0; c < TABLE_WITH_DESC_GEOM.cols; c += 1) {
    const slotId = `COL_${c + 1}_HEADER`;
    next.push(
      placeText(slotId, overlay.colHeaders[c], {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 13,
        fontWeight: 700,
        color: '#FFFFFF',
        clipToSlot: true,
        lineHeight: 1.1,
      }, 'heading')
    );
  }

  // 4. 6 Row Labels
  for (let r = 0; r < TABLE_WITH_DESC_GEOM.rows; r += 1) {
    const slotId = `ROW_${r + 1}_LABEL`;
    next.push(
      placeText(slotId, overlay.rowLabels[r], {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 12.5,
        fontWeight: 700,
        color: '#FFFFFF',
        clipToSlot: true,
        lineHeight: 1.1,
      }, 'heading')
    );
  }

  // 5. 24 Data Cells
  for (let r = 0; r < TABLE_WITH_DESC_GEOM.rows; r += 1) {
    const rowNum = r + 1;
    for (let c = 0; c < TABLE_WITH_DESC_GEOM.cols; c += 1) {
      const colNum = c + 1;
      const slotId = `CELL_${rowNum}_${colNum}`;
      next.push(
        placeText(slotId, overlay.cells[r][c], {
          align: 'center',
          verticalAlign: 'center',
          fontSize: 12,
          fontWeight: 500,
          color: mergedPalette.textDark,
          clipToSlot: true,
          lineHeight: 1.25,
        }, 'body')
      );
    }
  }

  // 6. Vector SVG Chrome
  const chrome = tableWithDescriptionChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase());
    const graphic = specToTableWithDescriptionContent(spec, mergedPalette);
    return {
      id: prev?.id || newId('shp-tbldesc'),
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

function layoutTableWithDescription(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  if (Array.isArray(doc)) {
    return layoutTableWithDescriptionElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas);
  }
  const palette = themeTokens?.palette || themeTokens || {};
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  };
  return { ...doc, elements: layoutTableWithDescriptionElements(doc.elements || [], layoutSchema, palette, size) };
}

module.exports = {
  TABLE_WITH_DESC_GEOM,
  TABLE_WITH_DESC_PALETTE,
  TABLE_WITH_DESC_DEFAULTS,
  isTableWithDescriptionLayout,
  isTableWithDescriptionTextSlot,
  layoutTableWithDescription,
};
