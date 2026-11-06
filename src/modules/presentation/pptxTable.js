/**
 * Native PPTX tables that look like the editor's.
 *
 * The editor draws a table on a card (white 92%, 1px border, rounded corners, 8px padding)
 * with collapsed 1px borders, a shaded bold header row and small text — all from CSS. The
 * render page measures that as drawn (exportRenderSettle.measureTables); this turns the
 * measurement into a rounded-rectangle card plus an editable table with the same column
 * widths, row heights, fills, ink, fonts, padding and borders. Without a measurement it uses
 * the editor's CSS defaults.
 *
 * Measurements are editor-stage px; `pt(px)` converts to points, `inch(px)` to inches.
 */

const EDITOR_TABLE_DEFAULTS = {
  card: { bg: '#FFFFFF', alpha: 0.92, border: { w: 1, color: '#94A3B8', alpha: 0.35 }, radius: 8, padding: 8 },
  fontSize: 10,
  pad: [2, 4, 2, 4],
  border: { w: 1, color: '#E2E8F0' },
  headerBg: '#F1F5F9',
  ink: '#111111',
};

const noHash = (c) => (c ? String(c).replace(/^#/, '').toUpperCase() : null);

function cellRowsFromContent(content = {}) {
  if (Array.isArray(content.cells)) return content.cells;
  if (Array.isArray(content.rows)) return content.rows.map((row) => (Array.isArray(row) ? row : [row]));
  return [];
}

/** A measurement in the editor's CSS defaults (no render page). */
function defaultMeasurement(content, box, stageW, stageH) {
  const rows = cellRowsFromContent(content);
  const cols = Math.max(1, ...rows.map((r) => r.length));
  const pad = EDITOR_TABLE_DEFAULTS.card.padding;
  const w = Math.max(10, stageW - pad * 2);
  const h = Math.max(10, stageH - pad * 2);
  const header = content.hasHeader !== false;
  return {
    card: EDITOR_TABLE_DEFAULTS.card,
    table: { x: pad, y: pad, w, h },
    cols: Array.from({ length: cols }, () => w / cols),
    rows: rows.map(() => h / Math.max(1, rows.length)),
    cells: rows.map((row, ri) =>
      Array.from({ length: cols }, (_, ci) => ({
        text: String(row[ci] ?? ''),
        bg: header && ri === 0 ? EDITOR_TABLE_DEFAULTS.headerBg : null,
        color: EDITOR_TABLE_DEFAULTS.ink,
        fontSize: EDITOR_TABLE_DEFAULTS.fontSize,
        fontWeight: header && ri === 0 ? 700 : 400,
        align: 'left',
        valign: 'middle',
        pad: EDITOR_TABLE_DEFAULTS.pad,
        border: Array(4).fill(EDITOR_TABLE_DEFAULTS.border),
      }))
    ),
  };
}

function cellValign(v) {
  const value = String(v || '').toLowerCase();
  if (value === 'top' || value === 'text-top') return 'top';
  if (value === 'bottom' || value === 'text-bottom') return 'bottom';
  return 'middle';
}

/**
 * Shapes and table to add for one table element.
 * @param {object} args
 * @param {object} args.content     element content
 * @param {object} args.box         element box, inches
 * @param {object|null} args.measured  measureTables() entry for the element
 * @param {(px:number)=>number} args.inch  stage px → inches
 * @param {(px:number)=>number} args.pt    stage px → points
 * @param {number} args.stageW / stageH    element size in stage px (for defaults)
 * @param {string|null} args.fontFace
 * @returns {{ card: object|null, rows: object[][], options: object } | null}
 */
function buildPptxTable({ content, box, measured, inch, pt, stageW, stageH, fontFace = null }) {
  const m = measured?.cells?.length ? measured : defaultMeasurement(content, box, stageW, stageH);
  if (!m.cells.length) return null;

  let card = null;
  if (m.card && (m.card.bg || m.card.border?.color)) {
    card = {
      x: box.x,
      y: box.y,
      w: box.w,
      h: box.h,
      rectRadius: Math.min(inch(m.card.radius || 0), Math.min(box.w, box.h) / 2),
      fill: m.card.bg
        ? { color: noHash(m.card.bg), ...(m.card.alpha < 1 ? { transparency: Math.round((1 - m.card.alpha) * 100) } : {}) }
        : undefined,
      line:
        m.card.border?.color && m.card.border.w > 0
          ? {
              color: noHash(m.card.border.color),
              width: Math.max(0.25, pt(m.card.border.w)),
              ...(m.card.border.alpha < 1 ? { transparency: Math.round((1 - m.card.border.alpha) * 100) } : {}),
            }
          : { type: 'none' },
    };
  }

  const borderOf = (b) =>
    b && b.color && b.w > 0 ? { type: 'solid', pt: Math.max(0.25, pt(b.w)), color: noHash(b.color) } : { type: 'none' };

  const rows = m.cells.map((row) =>
    row.map((cell) => ({
      text: String(cell.text ?? ''),
      options: {
        ...(cell.colSpan > 1 ? { colspan: cell.colSpan } : {}),
        ...(cell.bg ? { fill: { color: noHash(cell.bg) } } : {}),
        color: noHash(cell.color) || '111111',
        fontSize: Math.max(4, Math.round(pt(cell.fontSize || 10) * 10) / 10),
        bold: Number(cell.fontWeight) >= 600,
        italic: Boolean(cell.italic),
        align: ['left', 'center', 'right', 'justify'].includes(cell.align) ? cell.align : 'left',
        valign: cellValign(cell.valign),
        ...((cell.fontFamily || fontFace) ? { fontFace: cell.fontFamily || fontFace } : {}),
        // pptxgenjs: [top, right, bottom, left]; values under 1 are read as inches.
        margin: (cell.pad || [0, 0, 0, 0]).map((v) => Math.min(0.99, inch(v))),
        border: (cell.border || []).map(borderOf),
      },
    }))
  );

  const options = {
    x: box.x + inch(m.table.x),
    y: box.y + inch(m.table.y),
    w: inch(m.table.w),
    colW: m.cols.map((c) => inch(c)),
    rowH: m.rows.map((r) => inch(r)),
    autoPage: false,
  };
  return { card, rows, options };
}

module.exports = { buildPptxTable, EDITOR_TABLE_DEFAULTS };
