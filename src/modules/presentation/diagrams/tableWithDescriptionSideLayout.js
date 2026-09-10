/**
 * Table with Description Side Layout (Backend CommonJS)
 * Layout ID: table_with_description_side_v1
 * Features:
 *  - Centered Header: Title ("Table Slide") + Subtitle
 *  - Table on LEFT:
 *    - 4 columns with outline vector icons above headers (Clipboard, Documents, Archive, Photo)
 *    - Gradient-themed column headers: Deep Navy, Ocean Blue, Vivid Teal, Sky Blue
 *    - 5 rows with card cells containing clean, readable text & metrics
 *  - Description on RIGHT:
 *    - Side heading ("Project Planning") + multi-line descriptive text
 *  - Fully theme-responsive and recolorable
 */

const TABLE_SIDE_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Top centered header
  headingX: 60,
  headingY: 20,
  headingW: 880,
  headingH: 34,

  subtitleX: 60,
  subtitleY: 56,
  subtitleW: 880,
  subtitleH: 22,

  // Table on LEFT side
  tableX: 44,
  tableW: 580,
  cols: 4,
  colW: 142,
  colGap: 4,

  iconY: 96,
  iconH: 36,

  headerY: 136,
  headerH: 46,

  rowStartY: 186,
  rowH: 54,
  rowGap: 4,
  rows: 5,

  // Description on RIGHT side
  descCardX: 660,
  sideHeadingY: 196,
  sideHeadingW: 296,
  sideHeadingH: 32,

  sideBodyY: 236,
  sideBodyW: 296,
  sideBodyH: 150,
};

const TABLE_SIDE_PALETTE = {
  colHeaders: [
    '#004C87', // Col 1: Deep Navy Blue
    '#2A72B8', // Col 2: Ocean Blue
    '#00A896', // Col 3: Teal / Cyan
    '#0284C7', // Col 4: Sky/Ocean Blue
  ],
  iconColors: [
    '#004C87',
    '#2A72B8',
    '#00A896',
    '#0284C7',
  ],
  cellEven: '#FFFFFF',
  cellOdd: '#F8FAFC',
  cellBorder: '#E2E8F0',
  textDark: '#0F172A',
  textMuted: '#64748B',
  white: '#FFFFFF',
};

const TABLE_SIDE_DEFAULTS = {
  HEADING: 'Table Slide',
  SUBTITLE: 'Make a big impact with our professional slides and charts',

  COL_1_HEADER: 'Target',
  COL_2_HEADER: 'Sales',
  COL_3_HEADER: 'Execution',
  COL_4_HEADER: 'Control',

  SIDE_HEADING: 'Project Planning',
  BODY: 'Make a big impact with professional slides, charts, infographics and more. Turn complex data into easy to understand infographics.',
  DESCRIPTION: 'Make a big impact with professional slides, charts, infographics and more. Turn complex data into easy to understand infographics.',

  CELL_1_1: '10,000',
  CELL_1_2: '12,450',
  CELL_1_3: '98.5%',
  CELL_1_4: 'Approved',

  CELL_2_1: '15,000',
  CELL_2_2: '18,200',
  CELL_2_3: '94.2%',
  CELL_2_4: 'Pending',

  CELL_3_1: '20,000',
  CELL_3_2: '24,800',
  CELL_3_3: '99.1%',
  CELL_3_4: 'Complete',

  CELL_4_1: '25,000',
  CELL_4_2: '15,600',
  CELL_4_3: '96.4%',
  CELL_4_4: 'In Review',

  CELL_5_1: '30,000',
  CELL_5_2: '31,500',
  CELL_5_3: '97.8%',
  CELL_5_4: 'Verified',
};

function isTableWithDescriptionSideLayout(layoutId) {
  const s = String(layoutId || '').toLowerCase();
  return s === 'table_with_description_side_v1' || s === 'table_side_desc';
}

function isTableWithDescriptionSideTextSlot(slotId) {
  const s = String(slotId || '').toUpperCase();
  return (
    s === 'HEADING' ||
    s === 'SUBTITLE' ||
    s === 'SIDE_HEADING' ||
    s === 'BODY' ||
    s === 'DESCRIPTION' ||
    /^COL_\d+_HEADER$/i.test(s) ||
    /^CELL_\d+_\d+$/i.test(s)
  );
}

const COL_ICON_SVGS = [
  // 1. Checklist / Clipboard
  (c) => `<svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="${c}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/><path d="M9 12h6M9 16h6"/></svg>`,
  // 2. Documents / Stacked pages
  (c) => `<svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="${c}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>`,
  // 3. Storage Crate / File Box
  (c) => `<svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="${c}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>`,
  // 4. Photo Frame
  (c) => `<svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="${c}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>`,
];

function buildTableSideSvgChrome(palette = TABLE_SIDE_PALETTE) {
  const g = TABLE_SIDE_GEOM;
  const colHeaders = palette.colHeaders || TABLE_SIDE_PALETTE.colHeaders;
  const iconColors = palette.iconColors || TABLE_SIDE_PALETTE.iconColors;

  const svgParts = [];

  // 1. Column Icons & Header Tabs on LEFT
  for (let c = 0; c < g.cols; c += 1) {
    const colX = g.tableX + c * (g.colW + g.colGap);
    const color = colHeaders[c % colHeaders.length];
    const iconColor = iconColors[c % iconColors.length];
    const iconSvg = COL_ICON_SVGS[c % COL_ICON_SVGS.length](iconColor);

    svgParts.push(`
      <g transform="translate(${colX + (g.colW - 28) / 2}, ${g.iconY})">
        ${iconSvg}
      </g>
      <rect x="${colX}" y="${g.headerY}" width="${g.colW}" height="${g.headerH}" rx="6" fill="${color}" />
    `);
  }

  // 2. 5 Data Rows with Clean Card Cells
  for (let r = 0; r < g.rows; r += 1) {
    const rowY = g.rowStartY + r * (g.rowH + g.rowGap);
    const isEven = r % 2 === 0;
    const cellBg = isEven ? TABLE_SIDE_PALETTE.cellEven : TABLE_SIDE_PALETTE.cellOdd;

    for (let c = 0; c < g.cols; c += 1) {
      const colX = g.tableX + c * (g.colW + g.colGap);
      svgParts.push(`
        <rect x="${colX}" y="${rowY}" width="${g.colW}" height="${g.rowH}" rx="6" fill="${cellBg}" stroke="${TABLE_SIDE_PALETTE.cellBorder}" stroke-width="1" />
      `);
    }
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${g.viewW} ${g.viewH}" width="100%" height="100%" fill="none">${svgParts.join('\n')}</svg>`;
}

function tableSideChromeSpecs() {
  const g = TABLE_SIDE_GEOM;
  return [
    {
      slotId: 'TABLE_SIDE_CHROME',
      x: 0,
      y: 0,
      w: g.viewW,
      h: g.viewH,
      layer: 4,
    },
  ];
}

function tableSideOverlay(canvasW, canvasH) {
  const g = TABLE_SIDE_GEOM;
  const sx = canvasW / g.viewW;
  const sy = canvasH / g.viewH;

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

  const colHeaders = [];
  for (let c = 0; c < g.cols; c += 1) {
    const colX = g.tableX + c * (g.colW + g.colGap);
    colHeaders.push({
      x: Math.round((colX + 4) * sx),
      y: Math.round((g.headerY + 4) * sy),
      width: Math.round((g.colW - 8) * sx),
      height: Math.round((g.headerH - 8) * sy),
    });
  }

  const cells = [];
  for (let r = 0; r < g.rows; r += 1) {
    const rowCells = [];
    const rowY = g.rowStartY + r * (g.rowH + g.rowGap);
    for (let c = 0; c < g.cols; c += 1) {
      const colX = g.tableX + c * (g.colW + g.colGap);
      rowCells.push({
        x: Math.round((colX + 4) * sx),
        y: Math.round((rowY + 4) * sy),
        width: Math.round((g.colW - 8) * sx),
        height: Math.round((g.rowH - 8) * sy),
      });
    }
    cells.push(rowCells);
  }

  const sideHeading = {
    x: Math.round(g.descCardX * sx),
    y: Math.round(g.sideHeadingY * sy),
    width: Math.round(g.sideHeadingW * sx),
    height: Math.round(g.sideHeadingH * sy),
  };

  const sideBody = {
    x: Math.round(g.descCardX * sx),
    y: Math.round(g.sideBodyY * sy),
    width: Math.round(g.sideBodyW * sx),
    height: Math.round(g.sideBodyH * sy),
  };

  return {
    heading,
    subtitle,
    colHeaders,
    cells,
    sideHeading,
    sideBody,
  };
}

function specToTableSideContent(spec, palette) {
  return {
    svg: buildTableSideSvgChrome(palette),
    colorMode: 'recolorable',
    fill: palette?.primary || TABLE_SIDE_PALETTE.colHeaders[0],
  };
}

function newId(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}`;
}

function layoutTableWithDescriptionSideElements(elements, schema, palette = {}, canvas = {}) {
  if (!Array.isArray(elements)) return elements;
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const sx = canvasW / TABLE_SIDE_GEOM.viewW;
  const sy = canvasH / TABLE_SIDE_GEOM.viewH;

  const mergedPalette = {
    ...TABLE_SIDE_PALETTE,
    ...(palette?.primary ? {
      colHeaders: [
        palette.primary,
        palette.secondary || '#2A72B8',
        palette.accent || '#00A896',
        palette.accentLight || '#0284C7',
      ],
      iconColors: [
        palette.primary,
        palette.secondary || '#2A72B8',
        palette.accent || '#00A896',
        palette.accentLight || '#0284C7',
      ],
    } : {}),
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
    if (text !== undefined && text !== null) {
      const s = String(text).trim();
      // Discard dots / bullet circles from older templates so they cleanly upgrade to text
      if (s !== '' && s !== '●' && s !== '•' && s !== '·' && s !== '▪' && s !== '○') return s;
    }
    return fallback;
  };

  const overlay = tableSideOverlay(canvasW, canvasH);
  const next = [];

  const placeText = (slotId, box, style, role = 'body') => {
    const prev = prevBySlot.get(slotId.toUpperCase());
    const text = getText(slotId, TABLE_SIDE_DEFAULTS[slotId] || '');
    return {
      id: prev?.id || newId('txt-tblside'),
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

  // 1. Centered Header
  next.push(
    placeText('HEADING', overlay.heading, {
      align: 'center',
      verticalAlign: 'center',
      fontSize: 32,
      fontWeight: 800,
      color: mergedPalette.textDark,
      clipToSlot: true,
      lineHeight: 1.15,
    }, 'heading')
  );

  next.push(
    placeText('SUBTITLE', overlay.subtitle, {
      align: 'center',
      verticalAlign: 'center',
      fontSize: 14,
      fontWeight: 500,
      color: mergedPalette.textMuted,
      clipToSlot: true,
      lineHeight: 1.25,
    }, 'subheading')
  );

  // 2. 4 Column Headers
  for (let c = 0; c < TABLE_SIDE_GEOM.cols; c += 1) {
    const slotId = `COL_${c + 1}_HEADER`;
    next.push(
      placeText(slotId, overlay.colHeaders[c], {
        align: 'center',
        verticalAlign: 'center',
        fontSize: 14,
        fontWeight: 700,
        color: '#FFFFFF',
        clipToSlot: true,
        lineHeight: 1.1,
      }, 'heading')
    );
  }

  // 3. 20 Data Cells (Clean text and numbers instead of dots)
  for (let r = 0; r < TABLE_SIDE_GEOM.rows; r += 1) {
    const rowNum = r + 1;
    for (let c = 0; c < TABLE_SIDE_GEOM.cols; c += 1) {
      const colNum = c + 1;
      const slotId = `CELL_${rowNum}_${colNum}`;
      next.push(
        placeText(slotId, overlay.cells[r][c], {
          align: 'center',
          verticalAlign: 'center',
          fontSize: 13,
          fontWeight: 600,
          color: mergedPalette.textDark,
          clipToSlot: true,
          lineHeight: 1.2,
        }, 'body')
      );
    }
  }

  // 4. Description on the RIGHT
  next.push(
    placeText('SIDE_HEADING', overlay.sideHeading, {
      align: 'left',
      verticalAlign: 'center',
      fontSize: 22,
      fontWeight: 800,
      color: mergedPalette.textDark,
      clipToSlot: true,
      lineHeight: 1.2,
    }, 'heading')
  );

  const bodyText = getText('BODY', getText('DESCRIPTION', TABLE_SIDE_DEFAULTS.BODY));
  const prevBody = prevBySlot.get('BODY') || prevBySlot.get('DESCRIPTION');
  next.push({
    id: prevBody?.id || newId('txt-tblside'),
    type: 'text',
    role: 'body',
    layer: 14,
    slotId: 'BODY',
    placement: {
      x: overlay.sideBody.x,
      y: overlay.sideBody.y,
      width: overlay.sideBody.width,
      height: overlay.sideBody.height,
      rotation: 0,
      opacity: 1,
    },
    content: {
      text: bodyText,
      color: mergedPalette.textMuted,
      fontSize: 13.5,
      fontWeight: 400,
      align: 'left',
      verticalAlign: 'top',
      fontFamily: 'Inter, system-ui, sans-serif',
      lineHeight: 1.5,
      clipToSlot: true,
      padding: 0,
      paddingX: 0,
    },
  });

  // 5. Vector SVG Chrome (Outline icons, header cards, clean cells without dots)
  const chrome = tableSideChromeSpecs().map((spec) => {
    const prev = prevBySlot.get(spec.slotId.toUpperCase());
    const graphic = specToTableSideContent(spec, mergedPalette);
    return {
      id: prev?.id || newId('shp-tblside'),
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

function layoutTableWithDescriptionSide(doc, layoutSchema, themeTokens, canvas = {}) {
  if (!doc) return doc;
  if (Array.isArray(doc)) {
    return layoutTableWithDescriptionSideElements(doc, layoutSchema, themeTokens?.palette || themeTokens || {}, canvas);
  }
  const palette = themeTokens?.palette || themeTokens || {};
  const size = {
    width: canvas.width || doc.canvas?.width || 1920,
    height: canvas.height || doc.canvas?.height || 1080,
  };
  return { ...doc, elements: layoutTableWithDescriptionSideElements(doc.elements || [], layoutSchema, palette, size) };
}

module.exports = {
  TABLE_SIDE_GEOM,
  TABLE_SIDE_PALETTE,
  TABLE_SIDE_DEFAULTS,
  isTableWithDescriptionSideLayout,
  isTableWithDescriptionSideTextSlot,
  layoutTableWithDescriptionSide,
};
