/**
 * PPTX text boxes that match the editor: no PowerPoint default insets, the font size the
 * editor actually drew (fit-to-box), the editor's line height, lists, uppercase,
 * underline / strike / italic, letter spacing and links.
 *
 * Sizes in content are editor-stage px (the 900px-wide stage): they convert to points with
 * the slide width, like stagePxToPt in export.service.
 */

const { FONT_REF_WIDTH } = require('./textFit.util');
const { linkedRuns } = require('./textLinks');

/** Editor defaults (PptCanvasElement): font size 22, line height 1.25, no padding. */
const EDITOR_DEFAULT_FONT_PX = 22;
const EDITOR_DEFAULT_LINE_HEIGHT = 1.25;

const BULLET_CHAR_CODES = {
  bullet: '2022',
  star: '2605',
  check: '2713',
  dash: '2013',
};

function round1(n) {
  return Math.round(n * 10) / 10;
}

/** Editor-stage px → points on a slide `slideWidthIn` inches wide. */
function stagePxToPoints(px, slideWidthIn) {
  return ((Number(px) || 0) * slideWidthIn * 72) / FONT_REF_WIDTH;
}

/**
 * The size the editor drew: a fit-to-box measurement from the renderer when there is one
 * (never larger than the stored size), else the stored size.
 */
function resolveFontPx(content = {}, measured) {
  const stored = Number(content.fontSize) > 0 ? Number(content.fontSize) : EDITOR_DEFAULT_FONT_PX;
  const fitted = Number(measured?.fontSize);
  if (Number.isFinite(fitted) && fitted > 0) return Math.min(stored, fitted);
  return stored;
}

function applyTextTransform(text, transform) {
  const value = String(text ?? '');
  switch (String(transform || '').toLowerCase()) {
    case 'uppercase':
      return value.toUpperCase();
    case 'lowercase':
      return value.toLowerCase();
    case 'capitalize':
      return value.replace(/(^|\s)(\S)/g, (_, space, ch) => space + ch.toUpperCase());
    default:
      return value;
  }
}

/** CSS letter-spacing as the editor stores it: a number is stage px, a string may be em / px. */
function letterSpacingPoints(value, fontPt, slideWidthIn) {
  if (value == null || value === '') return null;
  if (typeof value === 'number') return round1(stagePxToPoints(value, slideWidthIn));
  const raw = String(value).trim();
  const num = parseFloat(raw);
  if (!Number.isFinite(num)) return null;
  if (/em$/i.test(raw)) return round1(num * fontPt);
  return round1(stagePxToPoints(num, slideWidthIn));
}

function bulletFor(listType) {
  const type = String(listType || '').toLowerCase();
  if (!type) return null;
  if (type === 'numbered' || type === 'number' || type === 'ordered') return { type: 'number' };
  return { characterCode: BULLET_CHAR_CODES[type] || BULLET_CHAR_CODES.bullet };
}

/** Pieces of text with their own style / link, in order. */
function textPieces(content = {}) {
  const runs = Array.isArray(content.runs) && content.runs.length ? content.runs : null;
  if (runs) return linkedRuns(runs);
  return linkedRuns([{ text: String(content.text ?? '') }]);
}

/** Split pieces into paragraphs at line breaks (each piece keeps its style). */
function splitParagraphs(pieces) {
  const paragraphs = [[]];
  for (const piece of pieces) {
    const parts = String(piece.text ?? '').replace(/\r\n?/g, '\n').split('\n');
    parts.forEach((part, i) => {
      if (i > 0) paragraphs.push([]);
      if (part) paragraphs[paragraphs.length - 1].push({ ...piece, text: part });
    });
  }
  return paragraphs;
}

/**
 * pptxgenjs `addText` arguments for an editor text element.
 *
 * @param {object} args
 * @param {object} args.content       element content
 * @param {{x:number,y:number,w:number,h:number}} args.box  inches
 * @param {number} args.rotate
 * @param {number} args.slideWidthIn
 * @param {string} args.color         resolved 6-digit hex for the box
 * @param {number|undefined} args.transparency
 * @param {string|null} args.fontFace
 * @param {(run:object)=>string} args.runColor  hex for a run with its own colour
 * @param {{fontSize?:number}|null} args.measured  what the renderer drew
 * @returns {{ runs: object[], options: object }}
 */
function buildPptxText({
  content = {},
  box,
  rotate = 0,
  slideWidthIn,
  color,
  transparency,
  fontFace,
  runColor,
  measured = null,
}) {
  const fontPx = resolveFontPx(content, measured);
  const fontPt = round1(stagePxToPoints(fontPx, slideWidthIn));
  const lineHeight = Number(content.lineHeight) > 0 ? Number(content.lineHeight) : EDITOR_DEFAULT_LINE_HEIGHT;
  const padY = Number(content.padding) > 0 ? stagePxToPoints(content.padding, slideWidthIn) : 0;
  const padXSource = content.paddingX != null ? content.paddingX : content.padding;
  const padX = Number(padXSource) > 0 ? stagePxToPoints(padXSource, slideWidthIn) : 0;
  const bold = content.bold === true || Number(content.fontWeight) >= 600;
  const charSpacing = letterSpacingPoints(content.letterSpacing, fontPt, slideWidthIn);
  const bullet = bulletFor(content.listType);
  const transform = content.textTransform;

  const baseRun = {
    fontSize: fontPt,
    bold,
    italic: content.italic === true,
    color,
    ...(fontFace ? { fontFace } : {}),
    ...(content.underline ? { underline: { style: 'sng' } } : {}),
    ...(content.strikethrough ? { strike: 'sngStrike' } : {}),
    ...(charSpacing ? { charSpacing } : {}),
    ...(transparency != null ? { transparency } : {}),
  };

  const paragraphs = splitParagraphs(textPieces(content));
  const runs = [];
  paragraphs.forEach((pieces, pIndex) => {
    const last = pIndex === paragraphs.length - 1;
    const paragraphOpts = bullet ? { bullet: { ...bullet, indent: round1(fontPt * 1.1) } } : {};
    const items = pieces.length ? pieces : [{ text: '' }];
    items.forEach((piece, i) => {
      const own = piece;
      // Every run carries the colour: a hyperlink run doesn't inherit the box colour.
      const options = {
        ...baseRun,
        ...paragraphOpts,
        ...(own.bold != null || Number(own.fontWeight) >= 600
          ? { bold: own.bold === true || Number(own.fontWeight) >= 600 }
          : {}),
        ...(own.italic != null ? { italic: own.italic === true } : {}),
        ...(own.underline ? { underline: { style: 'sng' } } : {}),
        ...(own.strikethrough ? { strike: 'sngStrike' } : {}),
        ...(own.fontFamily ? { fontFace: own.fontFamily } : {}),
        ...(own.fill || own.color || own.colorRole ? { color: runColor(own) } : {}),
        ...(own.href ? { hyperlink: { url: own.href, tooltip: own.href } } : {}),
      };
      if (!last && i === items.length - 1) options.breakLine = true;
      runs.push({ text: applyTextTransform(piece.text, transform), options });
    });
  });

  const valign = (() => {
    const v = String(content.verticalAlign || content.valign || '').toLowerCase();
    if (v === 'center' || v === 'middle') return 'middle';
    if (v === 'bottom' || v === 'flex-end' || v === 'end') return 'bottom';
    return 'top';
  })();

  const options = {
    x: box.x,
    y: box.y,
    w: box.w,
    h: box.h,
    rotate,
    align: ['left', 'center', 'right', 'justify'].includes(content.align) ? content.align : 'left',
    valign,
    // pptxgenjs order: left, right, bottom, top (points). An array is needed even for zero:
    // a plain 0 is ignored and PowerPoint then adds its own 0.1" / 0.05" insets.
    margin: [round1(padX), round1(padX), round1(padY), round1(padY)],
    // CSS line-height is exact, so is PowerPoint's "exactly" spacing.
    lineSpacing: round1(lineHeight * fontPt),
    // The editor already fitted the text: PowerPoint must not resize it again.
    fit: 'none',
    ...(content.wrap === 'nowrap' ? { wrap: false } : {}),
  };
  if (fontFace) options.fontFace = fontFace;

  return { runs, options, fontPt };
}

module.exports = {
  buildPptxText,
  resolveFontPx,
  stagePxToPoints,
  applyTextTransform,
  letterSpacingPoints,
  bulletFor,
  splitParagraphs,
  EDITOR_DEFAULT_FONT_PX,
  EDITOR_DEFAULT_LINE_HEIGHT,
};
