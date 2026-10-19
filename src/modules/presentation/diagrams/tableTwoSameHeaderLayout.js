/**
 * Table Two Same Header & Table Two Same Header Cards (Backend Server-Side Compiler)
 * Layout IDs:
 *  - table_two_same_header_v1: Executive side-by-side TABLES with shared column headers
 *  - table_two_same_header_cards_v1: Executive dual comparison CARDS with KPI summary boxes
 */

// ============================================================================
// 1. CARDS VARIANT (table_two_same_header_cards_v1)
// ============================================================================

const TABLE_TWO_SAME_HEADER_CARDS_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Header Area
  badgeX: 44,
  badgeY: 18,
  badgeW: 190,
  badgeH: 22,

  headingX: 44,
  headingY: 44,
  headingW: 912,
  headingH: 34,

  subtitleX: 44,
  subtitleY: 80,
  subtitleW: 912,
  subtitleH: 22,

  // Two Cards
  cardY: 112,
  cardH: 426,
  cardW: 444,
  cardGap: 24,
  card1X: 44,
  card2X: 512,
  cardRadius: 16,

  // Card Header
  iconOffset: 16,
  iconSize: 40,
  titleXOffset: 68,
  titleYOffset: 14,
  titleH: 24,
  badgeYOffset: 38,
  badgeH: 18,

  // Table Column Header Bar
  colBarXOffset: 16,
  colBarYOffset: 66,
  colBarW: 412,
  colBarH: 32,

  // Columns Widths (Total 412)
  col1W: 164,
  col2W: 124,
  col3W: 124,

  // Data Rows (3 rows to ensure executive breathing room & stay strictly within 50 elements)
  rowStartYOffset: 104,
  rowH: 48,
  rowsCount: 3,

  // KPI Summary Card at Bottom
  summaryYOffset: 262,
  summaryW: 412,
  summaryH: 146,
};

// ============================================================================
// 2. TABLE GRID VARIANT (table_two_same_header_v1)
// ============================================================================

const TABLE_TWO_SAME_HEADER_GEOM = {
  viewW: 1000,
  viewH: 560,

  // Header Area
  badgeX: 44,
  badgeY: 18,
  badgeW: 190,
  badgeH: 22,

  headingX: 44,
  headingY: 44,
  headingW: 912,
  headingH: 34,

  subtitleX: 44,
  subtitleY: 80,
  subtitleW: 912,
  subtitleH: 22,

  // Two Tables Geometry
  table1X: 44,
  table2X: 512,
  tableW: 444,
  tableGap: 24,

  // Table Title (Above Table Grid)
  titleY: 114,
  titleH: 28,

  // Table Grid Surface
  tableGridY: 146,
  headerH: 38,
  rowH: 48,
  rowsCount: 4,

  // Columns Widths (Total 444)
  col1W: 184,
  col2W: 130,
  col3W: 130,
};

const TABLE_TWO_SAME_HEADER_PALETTE = {
  t1: {
    primary: '#2563EB',
    cardBg: '#FFFFFF',
    cardBorder: '#BFDBFE',
    headerBg: '#EFF6FF',
    headerText: '#1E3A8A',
    iconBg: '#DBEAFE',
    iconColor: '#2563EB',
    badgeBg: '#EFF6FF',
    badgeText: '#2563EB',
    colBarBg: '#F1F5F9',
    colBarText: '#334155',
    rowEven: '#FFFFFF',
    rowOdd: '#F8FAFC',
    divider: '#E2E8F0',
    summaryBg: '#EFF6FF',
    summaryBorder: '#BFDBFE',
    summaryLabel: '#1E40AF',
    summaryValue: '#1E3A8A',
  },
  t2: {
    primary: '#7C3AED',
    cardBg: '#FFFFFF',
    cardBorder: '#DDD6FE',
    headerBg: '#FAF5FF',
    headerText: '#581C87',
    iconBg: '#EDE9FE',
    iconColor: '#7C3AED',
    badgeBg: '#FAF5FF',
    badgeText: '#7C3AED',
    colBarBg: '#F1F5F9',
    colBarText: '#334155',
    rowEven: '#FFFFFF',
    rowOdd: '#F8FAFC',
    divider: '#E2E8F0',
    summaryBg: '#FAF5FF',
    summaryBorder: '#DDD6FE',
    summaryLabel: '#6B21A8',
    summaryValue: '#581C87',
  },
};

const TABLE_TWO_SAME_HEADER_DEFAULTS = {
  BADGE: 'DUAL DATASET COMPARISON',
  HEADING: 'Side by side',
  SUBTITLE: 'Shared column headers across both operational datasets',

  // Shared Column Headers
  COL_A_HEADER: 'Performance Metric',
  COL_B_HEADER: 'Standard Tier',
  COL_C_HEADER: 'Enterprise Tier',

  // Table 1
  T1_TITLE: 'Dataset A — Standard',
  T1_BADGE: 'Production Baseline',
  T1_R1_LABEL: 'Response Latency',
  T1_R1_C1: '< 45 ms',
  T1_R1_C2: '< 12 ms',
  T1_R2_LABEL: 'Data Processing Speed',
  T1_R2_C1: '1.2 GB/sec',
  T1_R2_C2: '4.8 GB/sec',
  T1_R3_LABEL: 'Concurrent Requests',
  T1_R3_C1: '14,500/sec',
  T1_R3_C2: '50,000+/sec',
  T1_R4_LABEL: 'Uptime SLA',
  T1_R4_C1: '99.9%',
  T1_R4_C2: '99.99%',
  T1_TOTAL_LABEL: 'Overall Efficiency Benchmark',
  T1_TOTAL_SUB: 'Evaluated across 4 core production telemetry streams',
  T1_TOTAL_VALUE: '94.2 / 100',

  // Table 2
  T2_TITLE: 'Dataset B — Accelerated',
  T2_BADGE: 'Optimized Target',
  T2_R1_LABEL: 'Response Latency',
  T2_R1_C1: '< 20 ms',
  T2_R1_C2: '< 5 ms',
  T2_R2_LABEL: 'Data Processing Speed',
  T2_R2_C1: '2.8 GB/sec',
  T2_R2_C2: '12.0 GB/sec',
  T2_R3_LABEL: 'Concurrent Requests',
  T2_R3_C1: '38,000/sec',
  T2_R3_C2: '150,000+/sec',
  T2_R4_LABEL: 'Uptime SLA',
  T2_R4_C1: '99.95%',
  T2_R4_C2: '99.999%',
  T2_TOTAL_LABEL: 'Overall Efficiency Benchmark',
  T2_TOTAL_SUB: 'Evaluated across 4 core production telemetry streams',
  T2_TOTAL_VALUE: '98.7 / 100',
};

/** Check if layout ID is Table Two Same Header Cards variant */
function isTableTwoSameHeaderCardsLayout(layoutId) {
  const id = String(layoutId || '').toLowerCase();
  return (
    id === 'table_two_same_header_cards_v1' ||
    id === 'table_dual_shared_header_cards'
  );
}

/** Check if layout ID is Table Two Same Header (Table grid variant) */
function isTableTwoSameHeaderLayout(layoutId) {
  const id = String(layoutId || '').toLowerCase();
  if (isTableTwoSameHeaderCardsLayout(id)) return false;
  return (
    id === 'table_two_same_header_v1' ||
    id === 'table_dual_shared_header' ||
    id === 'table_two_same_header'
  );
}

// ============================================================================
// SVG BUILDERS
// ============================================================================

function buildCardContainerSvg(w, h, r = 16, borderColor = '#BFDBFE', isCardsVariant = true) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" fill="none" color="${borderColor}">
    <rect x="0.5" y="0.5" width="${w - 1}" height="${h - 1}" rx="${r}" fill="#FFFFFF" stroke="currentColor" stroke-width="${isCardsVariant ? '2' : '1.5'}" />
    <rect x="1" y="1" width="${w - 2}" height="6" rx="3" fill="currentColor" fill-opacity="0.25" />
  </svg>`;
}

function buildCardIconSvg(type = 'dataset', primaryColor = '#2563EB') {
  let iconPath = '';
  if (type === 'dataset') {
    iconPath = `
      <ellipse cx="12" cy="5" rx="8" ry="3" fill="none" stroke="currentColor" stroke-width="2" />
      <path d="M4 5v14c0 1.66 3.58 3 8 3s8-1.34 8-3V5" fill="none" stroke="currentColor" stroke-width="2" />
      <path d="M4 12c0 1.66 3.58 3 8 3s8-1.34 8-3" fill="none" stroke="currentColor" stroke-width="2" />
    `;
  } else {
    iconPath = `
      <line x1="18" y1="20" x2="18" y2="10" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
      <line x1="12" y1="20" x2="12" y2="4" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
      <line x1="6" y1="20" x2="6" y2="14" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
      <path d="M3 20h18" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
    `;
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40" width="100%" height="100%" fill="none" color="${primaryColor}">
    <rect x="0" y="0" width="40" height="40" rx="10" fill="currentColor" fill-opacity="0.12" />
    <g transform="translate(8, 8)">
      ${iconPath}
    </g>
  </svg>`;
}

function buildColBarSvg(w, h, bg = '#F1F5F9') {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" fill="none">
    <rect x="0" y="0" width="${w}" height="${h}" rx="6" fill="${bg}" />
  </svg>`;
}

function buildSummaryBoxSvg(w, h, color = '#2563EB') {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" fill="none" color="${color}">
    <rect x="0.5" y="0.5" width="${w - 1}" height="${h - 1}" rx="12" fill="currentColor" fill-opacity="0.05" stroke="currentColor" stroke-opacity="0.35" stroke-width="1.5" />
    <rect x="16" y="16" width="3" height="32" rx="1.5" fill="currentColor" />
  </svg>`;
}

function buildTableGridSvg(w, h, headerH = 38, rowsCount = 4, rowH = 48, primaryColor = '#2563EB') {
  let zebraRows = '';
  for (let r = 0; r < rowsCount; r += 1) {
    const ry = headerH + r * rowH;
    const isEven = r % 2 === 0;
    const fill = isEven ? '#FFFFFF' : '#F8FAFC';
    zebraRows += `
      <rect x="0.5" y="${ry}" width="${w - 1}" height="${rowH}" fill="${fill}" />
      <line x1="0" y1="${ry + rowH}" x2="${w}" y2="${ry + rowH}" stroke="#E2E8F0" stroke-width="1" />
    `;
  }

  const col1W = 184;
  const col2W = 130;

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="100%" height="100%" fill="none" color="${primaryColor}">
    <rect x="0.5" y="0.5" width="${w - 1}" height="${h - 1}" rx="8" fill="#FFFFFF" stroke="#CBD5E1" stroke-width="1.5" />
    <path d="M 0.5 8.5 Q 0.5 0.5 8.5 0.5 L ${w - 8.5} 0.5 Q ${w - 0.5} 0.5 ${w - 0.5} 8.5 L ${w - 0.5} 4.5 L 0.5 4.5 Z" fill="currentColor" />
    <rect x="0.5" y="4" width="${w - 1}" height="${headerH - 4}" fill="#F1F5F9" />
    <line x1="0" y1="${headerH}" x2="${w}" y2="${headerH}" stroke="#CBD5E1" stroke-width="1.5" />
    ${zebraRows}
    <line x1="${col1W}" y1="4" x2="${col1W}" y2="${h - 1}" stroke="#E2E8F0" stroke-width="1" stroke-dasharray="3 3" />
    <line x1="${col1W + col2W}" y1="4" x2="${col1W + col2W}" y2="${h - 1}" stroke="#E2E8F0" stroke-width="1" stroke-dasharray="3 3" />
  </svg>`;
}

// ============================================================================
// 3. COMPILER: TABLE VARIANT (table_two_same_header_v1)
// ============================================================================

function layoutTableTwoSameHeader(elements = [], schema = {}, palette = {}, canvas = {}) {
  const g = TABLE_TWO_SAME_HEADER_GEOM;
  const canvasW = canvas?.width || 1000;
  const canvasH = canvas?.height || 560;
  const scaleX = canvasW / g.viewW;
  const scaleY = canvasH / g.viewH;

  const safeElements = Array.isArray(elements) ? elements : [];
  const prevBySlot = new Map();
  safeElements.forEach((el) => {
    const sid = String(el.slotId || el.id || '').toUpperCase();
    if (sid) prevBySlot.set(sid, el);
  });

  const slots = Array.isArray(schema?.slots) ? schema.slots : [];

  const getPrevText = (slotId, fallback) => {
    const prev = prevBySlot.get(slotId);
    if (prev?.content?.text !== undefined && prev?.content?.text !== null) return prev.content.text;
    if (prev?.content?.html) return prev.content.html.replace(/<[^>]*>/g, '');
    const fromSlot = slots.find((s) => String(s.id).toUpperCase() === slotId);
    if (fromSlot?.placeholder_text) return fromSlot.placeholder_text;
    return fallback;
  };

  const newId = (prefix) => `${prefix}-${Math.random().toString(36).slice(2, 9)}`;
  const newElements = [];

  const pushElement = (el) => {
    const rawRect = el.rect || el.placement || {};
    const x = Math.round(rawRect.x || 0);
    const y = Math.round(rawRect.y || 0);
    const width = Math.max(1, Math.round(rawRect.width || 10));
    const height = Math.max(1, Math.round(rawRect.height || 10));

    newElements.push({
      ...el,
      placement: {
        x,
        y,
        width,
        height,
        rotation: 0,
        opacity: 1,
      },
      rect: {
        x,
        y,
        width,
        height,
      },
    });
  };

  const p1 = palette?.primary || TABLE_TWO_SAME_HEADER_PALETTE.t1.primary;
  const p2 = palette?.accent || TABLE_TWO_SAME_HEADER_PALETTE.t2.primary;
  const textColor = palette?.text || '#1E293B';
  const mutedColor = palette?.muted || '#64748B';

  // 1. Top Category Pill Badge
  pushElement({
    id: prevBySlot.get('TAG_BADGE')?.id || newId('table-tag-badge'),
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
      text: getPrevText('TAG_BADGE', TABLE_TWO_SAME_HEADER_DEFAULTS.BADGE),
      fontSize: 11,
      fontWeight: 700,
      color: p1,
      textTransform: 'uppercase',
      letterSpacing: '0.08em',
      clipToSlot: false,
    },
  });

  // 2. Heading
  const headingText =
    getPrevText('HEADING', '') ||
    getPrevText('TITLE', '') ||
    TABLE_TWO_SAME_HEADER_DEFAULTS.HEADING;

  pushElement({
    id: prevBySlot.get('HEADING')?.id || newId('table-heading'),
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
      text: headingText,
      fontSize: 28,
      fontWeight: 800,
      color: textColor,
      clipToSlot: false,
    },
  });

  // 3. Subtitle / Shared Header
  const subtitleText =
    getPrevText('SUBTITLE', '') ||
    getPrevText('TABLE_HEADER', '') ||
    TABLE_TWO_SAME_HEADER_DEFAULTS.SUBTITLE;

  pushElement({
    id: prevBySlot.get('SUBTITLE')?.id || prevBySlot.get('TABLE_HEADER')?.id || newId('table-sub'),
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
      text: subtitleText,
      fontSize: 14,
      fontWeight: 500,
      color: mutedColor,
      clipToSlot: false,
    },
  });

  // Helper to compile each table
  const buildTableSide = (isLeft) => {
    const prefix = isLeft ? 'T1' : 'T2';
    const pfxLower = isLeft ? 't1' : 't2';
    const tableX = isLeft ? g.table1X : g.table2X;
    const tableW = g.tableW;
    const tableColor = isLeft ? p1 : p2;
    const prevGrid = prevBySlot.get(prefix + '_TABLE_GRID') || prevBySlot.get(prefix + '_CARD');
    const activeColor = prevGrid?.content?.fill || tableColor;

    const gridH = g.headerH + g.rowsCount * g.rowH;

    // Table Title
    pushElement({
      id: prevBySlot.get(prefix + '_TITLE')?.id || newId(pfxLower + '-title'),
      type: 'text',
      slotId: prefix + '_TITLE',
      layer: 10,
      rect: {
        x: tableX * scaleX,
        y: g.titleY * scaleY,
        width: tableW * scaleX,
        height: g.titleH * scaleY,
      },
      content: {
        text: getPrevText(prefix + '_TITLE', TABLE_TWO_SAME_HEADER_DEFAULTS[prefix + '_TITLE']),
        fontSize: 18,
        fontWeight: 700,
        color: textColor,
        clipToSlot: false,
      },
    });

    // Table Grid Graphic Surface
    pushElement({
      id: prevGrid?.id || newId(pfxLower + '-grid'),
      type: 'graphic',
      slotId: prefix + '_TABLE_GRID',
      layer: 2,
      rect: {
        x: tableX * scaleX,
        y: g.tableGridY * scaleY,
        width: tableW * scaleX,
        height: gridH * scaleY,
      },
      content: {
        svg: buildTableGridSvg(tableW, gridH, g.headerH, g.rowsCount, g.rowH, activeColor),
        colorMode: 'recolorable',
        fill: activeColor,
        colorRole: isLeft ? 'primary' : 'accent',
      },
    });

    // Column Headers
    const colA_X = tableX + 14;
    const colB_X = tableX + g.col1W;
    const colC_X = colB_X + g.col2W;
    const colHeaderY = g.tableGridY + 10;

    pushElement({
      id: prevBySlot.get(prefix + '_COL_A_HEADER')?.id || newId(pfxLower + '-col-a'),
      type: 'text',
      slotId: prefix + '_COL_A_HEADER',
      layer: 10,
      rect: {
        x: colA_X * scaleX,
        y: colHeaderY * scaleY,
        width: (g.col1W - 20) * scaleX,
        height: 22 * scaleY,
      },
      content: {
        text: getPrevText(
          prefix + '_COL_A_HEADER',
          getPrevText('COL_A_HEADER', TABLE_TWO_SAME_HEADER_DEFAULTS.COL_A_HEADER)
        ),
        fontSize: 12,
        fontWeight: 700,
        color: '#334155',
        clipToSlot: false,
      },
    });

    pushElement({
      id: prevBySlot.get(prefix + '_COL_B_HEADER')?.id || newId(pfxLower + '-col-b'),
      type: 'text',
      slotId: prefix + '_COL_B_HEADER',
      layer: 10,
      rect: {
        x: colB_X * scaleX,
        y: colHeaderY * scaleY,
        width: (g.col2W - 8) * scaleX,
        height: 22 * scaleY,
      },
      content: {
        text: getPrevText(
          prefix + '_COL_B_HEADER',
          getPrevText('COL_B_HEADER', TABLE_TWO_SAME_HEADER_DEFAULTS.COL_B_HEADER)
        ),
        fontSize: 12,
        fontWeight: 700,
        color: '#334155',
        textAlign: 'center',
        clipToSlot: false,
      },
    });

    pushElement({
      id: prevBySlot.get(prefix + '_COL_C_HEADER')?.id || newId(pfxLower + '-col-c'),
      type: 'text',
      slotId: prefix + '_COL_C_HEADER',
      layer: 10,
      rect: {
        x: colC_X * scaleX,
        y: colHeaderY * scaleY,
        width: (g.col3W - 8) * scaleX,
        height: 22 * scaleY,
      },
      content: {
        text: getPrevText(
          prefix + '_COL_C_HEADER',
          getPrevText('COL_C_HEADER', TABLE_TWO_SAME_HEADER_DEFAULTS.COL_C_HEADER)
        ),
        fontSize: 12,
        fontWeight: 700,
        color: '#334155',
        textAlign: 'center',
        clipToSlot: false,
      },
    });

    // Data Rows (4 Rows)
    for (let r = 1; r <= g.rowsCount; r += 1) {
      const rowY = g.tableGridY + g.headerH + (r - 1) * g.rowH;
      const rowTextY = rowY + 14;

      // Metric Label
      pushElement({
        id: prevBySlot.get(prefix + '_R' + r + '_LABEL')?.id || newId(pfxLower + '-r' + r + '-lbl'),
        type: 'text',
        slotId: prefix + '_R' + r + '_LABEL',
        layer: 10,
        rect: {
          x: colA_X * scaleX,
          y: rowTextY * scaleY,
          width: (g.col1W - 20) * scaleX,
          height: 22 * scaleY,
        },
        content: {
          text: getPrevText(prefix + '_R' + r + '_LABEL', TABLE_TWO_SAME_HEADER_DEFAULTS[prefix + '_R' + r + '_LABEL']),
          fontSize: 13,
          fontWeight: 600,
          color: textColor,
          clipToSlot: false,
        },
      });

      // Col B Value
      pushElement({
        id: prevBySlot.get(prefix + '_R' + r + '_C1')?.id || newId(pfxLower + '-r' + r + '-c1'),
        type: 'text',
        slotId: prefix + '_R' + r + '_C1',
        layer: 10,
        rect: {
          x: colB_X * scaleX,
          y: rowTextY * scaleY,
          width: (g.col2W - 8) * scaleX,
          height: 22 * scaleY,
        },
        content: {
          text: getPrevText(prefix + '_R' + r + '_C1', TABLE_TWO_SAME_HEADER_DEFAULTS[prefix + '_R' + r + '_C1']),
          fontSize: 13,
          fontWeight: 500,
          color: mutedColor,
          textAlign: 'center',
          clipToSlot: false,
        },
      });

      // Col C Value
      pushElement({
        id: prevBySlot.get(prefix + '_R' + r + '_C2')?.id || newId(pfxLower + '-r' + r + '-c2'),
        type: 'text',
        slotId: prefix + '_R' + r + '_C2',
        layer: 10,
        rect: {
          x: colC_X * scaleX,
          y: rowTextY * scaleY,
          width: (g.col3W - 8) * scaleX,
          height: 22 * scaleY,
        },
        content: {
          text: getPrevText(prefix + '_R' + r + '_C2', TABLE_TWO_SAME_HEADER_DEFAULTS[prefix + '_R' + r + '_C2']),
          fontSize: 13,
          fontWeight: 700,
          color: textColor,
          textAlign: 'center',
          clipToSlot: false,
        },
      });
    }
  };

  buildTableSide(true);
  buildTableSide(false);

  return newElements;
}

// ============================================================================
// 4. COMPILER: CARDS VARIANT (table_two_same_header_cards_v1)
// ============================================================================

function layoutTableTwoSameHeaderCards(elements = [], schema = {}, palette = {}, canvas = {}) {
  const g = TABLE_TWO_SAME_HEADER_CARDS_GEOM;
  const canvasW = canvas?.width || 1000;
  const canvasH = canvas?.height || 560;
  const scaleX = canvasW / g.viewW;
  const scaleY = canvasH / g.viewH;

  const safeElements = Array.isArray(elements) ? elements : [];
  const prevBySlot = new Map();
  safeElements.forEach((el) => {
    const sid = String(el.slotId || el.id || '').toUpperCase();
    if (sid) prevBySlot.set(sid, el);
  });

  const slots = Array.isArray(schema?.slots) ? schema.slots : [];

  const getPrevText = (slotId, fallback) => {
    const prev = prevBySlot.get(slotId);
    if (prev?.content?.text !== undefined && prev?.content?.text !== null) return prev.content.text;
    if (prev?.content?.html) return prev.content.html.replace(/<[^>]*>/g, '');
    const fromSlot = slots.find((s) => String(s.id).toUpperCase() === slotId);
    if (fromSlot?.placeholder_text) return fromSlot.placeholder_text;
    return fallback;
  };

  const newId = (prefix) => `${prefix}-${Math.random().toString(36).slice(2, 9)}`;
  const newElements = [];

  const pushElement = (el) => {
    const rawRect = el.rect || el.placement || {};
    const x = Math.round(rawRect.x || 0);
    const y = Math.round(rawRect.y || 0);
    const width = Math.max(1, Math.round(rawRect.width || 10));
    const height = Math.max(1, Math.round(rawRect.height || 10));

    newElements.push({
      ...el,
      placement: {
        x,
        y,
        width,
        height,
        rotation: 0,
        opacity: 1,
      },
      rect: {
        x,
        y,
        width,
        height,
      },
    });
  };

  const p1 = palette?.primary || TABLE_TWO_SAME_HEADER_PALETTE.t1.primary;
  const p2 = palette?.accent || TABLE_TWO_SAME_HEADER_PALETTE.t2.primary;
  const textColor = palette?.text || '#1E293B';
  const mutedColor = palette?.muted || '#64748B';

  // 1. Top Category Pill Badge
  pushElement({
    id: prevBySlot.get('TAG_BADGE')?.id || newId('table-tag-badge'),
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
      text: getPrevText('TAG_BADGE', TABLE_TWO_SAME_HEADER_DEFAULTS.BADGE),
      fontSize: 11,
      fontWeight: 700,
      color: p1,
      textTransform: 'uppercase',
      letterSpacing: '0.08em',
      clipToSlot: false,
    },
  });

  // 2. Heading
  const headingText =
    getPrevText('HEADING', '') ||
    getPrevText('TITLE', '') ||
    TABLE_TWO_SAME_HEADER_DEFAULTS.HEADING;

  pushElement({
    id: prevBySlot.get('HEADING')?.id || newId('table-heading'),
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
      text: headingText,
      fontSize: 28,
      fontWeight: 800,
      color: textColor,
      clipToSlot: false,
    },
  });

  // 3. Subtitle / Shared Header
  const subtitleText =
    getPrevText('SUBTITLE', '') ||
    getPrevText('TABLE_HEADER', '') ||
    TABLE_TWO_SAME_HEADER_DEFAULTS.SUBTITLE;

  pushElement({
    id: prevBySlot.get('SUBTITLE')?.id || prevBySlot.get('TABLE_HEADER')?.id || newId('table-sub'),
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
      text: subtitleText,
      fontSize: 14,
      fontWeight: 500,
      color: mutedColor,
      clipToSlot: false,
    },
  });

  // Helper to compile each table card
  const buildTableSide = (isLeft) => {
    const prefix = isLeft ? 'T1' : 'T2';
    const pfxLower = isLeft ? 't1' : 't2';
    const cardX = isLeft ? g.card1X : g.card2X;
    const cardY = g.cardY;
    const cardW = g.cardW;
    const cardH = g.cardH;
    const cardColor = isLeft ? p1 : p2;
    const prevCard = prevBySlot.get(prefix + '_CARD');
    const activeColor = prevCard?.content?.fill || cardColor;

    // 1. Card Container Graphic
    pushElement({
      id: prevCard?.id || newId(pfxLower + '-card'),
      type: 'graphic',
      slotId: prefix + '_CARD',
      layer: 2,
      rect: {
        x: cardX * scaleX,
        y: cardY * scaleY,
        width: cardW * scaleX,
        height: cardH * scaleY,
      },
      content: {
        svg: buildCardContainerSvg(cardW, cardH, g.cardRadius, activeColor, true),
        colorMode: 'recolorable',
        fill: activeColor,
        colorRole: isLeft ? 'primary' : 'accent',
      },
    });

    // 2. Card Icon Graphic (Only if not deleted by user)
    const prevIcon = prevBySlot.get(prefix + '_ICON')
    const wasIconDeleted = prevBySlot.has(prefix + '_CARD') && !prevIcon
    if (!wasIconDeleted) {
      const iconActiveColor = prevIcon?.content?.fill || activeColor
      pushElement({
        id: prevIcon?.id || newId(pfxLower + '-icon'),
        type: 'graphic',
        slotId: prefix + '_ICON',
        layer: 5,
        rect: {
          x: (cardX + g.iconOffset) * scaleX,
          y: (cardY + g.iconOffset) * scaleY,
          width: g.iconSize * scaleX,
          height: g.iconSize * scaleY,
        },
        content: {
          svg: buildCardIconSvg(isLeft ? 'dataset' : 'analytics', iconActiveColor),
          colorMode: 'recolorable',
          fill: iconActiveColor,
        },
      });
    }

    // 3. Card Title Text
    pushElement({
      id: prevBySlot.get(prefix + '_TITLE')?.id || newId(pfxLower + '-title'),
      type: 'text',
      slotId: prefix + '_TITLE',
      layer: 10,
      rect: {
        x: (cardX + g.titleXOffset) * scaleX,
        y: (cardY + g.titleYOffset) * scaleY,
        width: 250 * scaleX,
        height: g.titleH * scaleY,
      },
      content: {
        text: getPrevText(prefix + '_TITLE', TABLE_TWO_SAME_HEADER_DEFAULTS[prefix + '_TITLE']),
        fontSize: 17,
        fontWeight: 700,
        color: textColor,
        clipToSlot: false,
      },
    });

    // 4. Card Sub-Badge Text
    pushElement({
      id: prevBySlot.get(prefix + '_BADGE')?.id || newId(pfxLower + '-badge'),
      type: 'text',
      slotId: prefix + '_BADGE',
      layer: 10,
      rect: {
        x: (cardX + g.titleXOffset) * scaleX,
        y: (cardY + g.badgeYOffset) * scaleY,
        width: 250 * scaleX,
        height: g.badgeH * scaleY,
      },
      content: {
        text: getPrevText(prefix + '_BADGE', TABLE_TWO_SAME_HEADER_DEFAULTS[prefix + '_BADGE']),
        fontSize: 12,
        fontWeight: 600,
        color: activeColor,
        clipToSlot: false,
      },
    });

    // 5. Column Header Bar Graphic
    pushElement({
      id: prevBySlot.get(prefix + '_COL_BAR')?.id || newId(pfxLower + '-colbar'),
      type: 'graphic',
      slotId: prefix + '_COL_BAR',
      layer: 3,
      rect: {
        x: (cardX + g.colBarXOffset) * scaleX,
        y: (cardY + g.colBarYOffset) * scaleY,
        width: g.colBarW * scaleX,
        height: g.colBarH * scaleY,
      },
      content: {
        svg: buildColBarSvg(g.colBarW, g.colBarH, '#F1F5F9'),
        colorMode: 'recolorable',
        fill: '#F1F5F9',
      },
    });

    // 6. Shared Column Header Texts
    const colA_X = cardX + g.colBarXOffset + 12;
    const colB_X = colA_X + g.col1W;
    const colC_X = colB_X + g.col2W;
    const colHeaderY = cardY + g.colBarYOffset + 7;

    pushElement({
      id: prevBySlot.get(prefix + '_COL_A_HEADER')?.id || newId(pfxLower + '-col-a'),
      type: 'text',
      slotId: prefix + '_COL_A_HEADER',
      layer: 10,
      rect: {
        x: colA_X * scaleX,
        y: colHeaderY * scaleY,
        width: (g.col1W - 8) * scaleX,
        height: 20 * scaleY,
      },
      content: {
        text: getPrevText(
          prefix + '_COL_A_HEADER',
          getPrevText('COL_A_HEADER', TABLE_TWO_SAME_HEADER_DEFAULTS.COL_A_HEADER)
        ),
        fontSize: 12,
        fontWeight: 700,
        color: '#334155',
        clipToSlot: false,
      },
    });

    pushElement({
      id: prevBySlot.get(prefix + '_COL_B_HEADER')?.id || newId(pfxLower + '-col-b'),
      type: 'text',
      slotId: prefix + '_COL_B_HEADER',
      layer: 10,
      rect: {
        x: colB_X * scaleX,
        y: colHeaderY * scaleY,
        width: (g.col2W - 8) * scaleX,
        height: 20 * scaleY,
      },
      content: {
        text: getPrevText(
          prefix + '_COL_B_HEADER',
          getPrevText('COL_B_HEADER', TABLE_TWO_SAME_HEADER_DEFAULTS.COL_B_HEADER)
        ),
        fontSize: 12,
        fontWeight: 700,
        color: '#334155',
        textAlign: 'center',
        clipToSlot: false,
      },
    });

    pushElement({
      id: prevBySlot.get(prefix + '_COL_C_HEADER')?.id || newId(pfxLower + '-col-c'),
      type: 'text',
      slotId: prefix + '_COL_C_HEADER',
      layer: 10,
      rect: {
        x: colC_X * scaleX,
        y: colHeaderY * scaleY,
        width: (g.col3W - 8) * scaleX,
        height: 20 * scaleY,
      },
      content: {
        text: getPrevText(
          prefix + '_COL_C_HEADER',
          getPrevText('COL_C_HEADER', TABLE_TWO_SAME_HEADER_DEFAULTS.COL_C_HEADER)
        ),
        fontSize: 12,
        fontWeight: 700,
        color: '#334155',
        textAlign: 'center',
        clipToSlot: false,
      },
    });

    // 7. Data Rows (3 Rows)
    for (let r = 1; r <= g.rowsCount; r += 1) {
      const rowY = cardY + g.rowStartYOffset + (r - 1) * g.rowH;
      const rowTextY = rowY + 11;

      // Row Label (Col A)
      pushElement({
        id: prevBySlot.get(prefix + '_R' + r + '_LABEL')?.id || newId(pfxLower + '-r' + r + '-lbl'),
        type: 'text',
        slotId: prefix + '_R' + r + '_LABEL',
        layer: 10,
        rect: {
          x: colA_X * scaleX,
          y: rowTextY * scaleY,
          width: (g.col1W - 8) * scaleX,
          height: 22 * scaleY,
        },
        content: {
          text: getPrevText(prefix + '_R' + r + '_LABEL', TABLE_TWO_SAME_HEADER_DEFAULTS[prefix + '_R' + r + '_LABEL']),
          fontSize: 13,
          fontWeight: 600,
          color: textColor,
          clipToSlot: false,
        },
      });

      // Col B Value
      pushElement({
        id: prevBySlot.get(prefix + '_R' + r + '_C1')?.id || newId(pfxLower + '-r' + r + '-c1'),
        type: 'text',
        slotId: prefix + '_R' + r + '_C1',
        layer: 10,
        rect: {
          x: colB_X * scaleX,
          y: rowTextY * scaleY,
          width: (g.col2W - 8) * scaleX,
          height: 22 * scaleY,
        },
        content: {
          text: getPrevText(prefix + '_R' + r + '_C1', TABLE_TWO_SAME_HEADER_DEFAULTS[prefix + '_R' + r + '_C1']),
          fontSize: 13,
          fontWeight: 500,
          color: mutedColor,
          textAlign: 'center',
          clipToSlot: false,
        },
      });

      // Col C Value
      pushElement({
        id: prevBySlot.get(prefix + '_R' + r + '_C2')?.id || newId(pfxLower + '-r' + r + '-c2'),
        type: 'text',
        slotId: prefix + '_R' + r + '_C2',
        layer: 10,
        rect: {
          x: colC_X * scaleX,
          y: rowTextY * scaleY,
          width: (g.col3W - 8) * scaleX,
          height: 22 * scaleY,
        },
        content: {
          text: getPrevText(prefix + '_R' + r + '_C2', TABLE_TWO_SAME_HEADER_DEFAULTS[prefix + '_R' + r + '_C2']),
          fontSize: 13,
          fontWeight: 700,
          color: textColor,
          textAlign: 'center',
          clipToSlot: false,
        },
      });
    }

    // 8. Bottom KPI Summary Box Graphic
    const prevSummary = prevBySlot.get(prefix + '_TOTAL_BOX');
    const summaryColor = prevSummary?.content?.fill || activeColor;
    pushElement({
      id: prevSummary?.id || newId(pfxLower + '-sum-box'),
      type: 'graphic',
      slotId: prefix + '_TOTAL_BOX',
      layer: 3,
      rect: {
        x: (cardX + g.colBarXOffset) * scaleX,
        y: (cardY + g.summaryYOffset) * scaleY,
        width: g.summaryW * scaleX,
        height: (g.summaryH - 4) * scaleY,
      },
      content: {
        svg: buildSummaryBoxSvg(g.summaryW, g.summaryH - 4, summaryColor),
        colorMode: 'recolorable',
        fill: summaryColor,
      },
    });

    // 9. Summary Title & Subtitle Texts
    pushElement({
      id: prevBySlot.get(prefix + '_TOTAL_LABEL')?.id || newId(pfxLower + '-total-lbl'),
      type: 'text',
      slotId: prefix + '_TOTAL_LABEL',
      layer: 10,
      rect: {
        x: (cardX + g.colBarXOffset + 28) * scaleX,
        y: (cardY + g.summaryYOffset + 16) * scaleY,
        width: 250 * scaleX,
        height: 20 * scaleY,
      },
      content: {
        text: getPrevText(prefix + '_TOTAL_LABEL', TABLE_TWO_SAME_HEADER_DEFAULTS[prefix + '_TOTAL_LABEL']),
        fontSize: 13,
        fontWeight: 700,
        color: activeColor,
        clipToSlot: false,
      },
    });

    pushElement({
      id: prevBySlot.get(prefix + '_TOTAL_SUB')?.id || newId(pfxLower + '-total-sub'),
      type: 'text',
      slotId: prefix + '_TOTAL_SUB',
      layer: 10,
      rect: {
        x: (cardX + g.colBarXOffset + 28) * scaleX,
        y: (cardY + g.summaryYOffset + 38) * scaleY,
        width: 250 * scaleX,
        height: 38 * scaleY,
      },
      content: {
        text: getPrevText(prefix + '_TOTAL_SUB', TABLE_TWO_SAME_HEADER_DEFAULTS[prefix + '_TOTAL_SUB']),
        fontSize: 11,
        fontWeight: 400,
        color: mutedColor,
        clipToSlot: false,
      },
    });

    // 10. Summary KPI Big Value Text
    pushElement({
      id: prevBySlot.get(prefix + '_TOTAL_VALUE')?.id || newId(pfxLower + '-total-val'),
      type: 'text',
      slotId: prefix + '_TOTAL_VALUE',
      layer: 10,
      rect: {
        x: (cardX + cardW - 148) * scaleX,
        y: (cardY + g.summaryYOffset + 20) * scaleY,
        width: 130 * scaleX,
        height: 36 * scaleY,
      },
      content: {
        text: getPrevText(prefix + '_TOTAL_VALUE', TABLE_TWO_SAME_HEADER_DEFAULTS[prefix + '_TOTAL_VALUE']),
        fontSize: 22,
        fontWeight: 800,
        color: textColor,
        textAlign: 'right',
        clipToSlot: false,
      },
    });
  };

  buildTableSide(true);
  buildTableSide(false);

  return newElements;
}

module.exports = {
  TABLE_TWO_SAME_HEADER_GEOM,
  TABLE_TWO_SAME_HEADER_CARDS_GEOM,
  TABLE_TWO_SAME_HEADER_PALETTE,
  TABLE_TWO_SAME_HEADER_DEFAULTS,
  isTableTwoSameHeaderLayout,
  isTableTwoSameHeaderCardsLayout,
  layoutTableTwoSameHeader,
  layoutTableTwoSameHeaderCards,
};
