'use strict';

/**
 * Generation-time text fitting.
 *
 * Layout typography is authored in "editor stage" pixels (~900px-wide stage; see the
 * viewW:1000 diagram geometry), while placements are in canvas pixels (1920x1080). A title
 * that is fine at 56px on paper can therefore wrap to 3+ lines in an 800px canvas slot and
 * spill into the next element. This pass estimates the wrapped height of every text element
 * and shrinks its font size (never grows it) until it fits the placement box.
 */

const FONT_REF_WIDTH = 900;
const MIN_FONT_RATIO = 0.45;
const MIN_FONT_PX = 9;

function avgCharWidthEm(content) {
  let em = 0.5;
  const weight = Number(content?.fontWeight) || (content?.bold ? 700 : 400);
  if (weight >= 700) em += 0.04;
  if (String(content?.textTransform || '').toLowerCase() === 'uppercase') em *= 1.15;
  const letterSpacing = Number(content?.letterSpacing);
  if (Number.isFinite(letterSpacing) && letterSpacing > 0) em += letterSpacing;
  return em;
}

function estimateLineCount(text, charsPerLine) {
  const limit = Math.max(1, Math.floor(charsPerLine));
  let lines = 0;
  for (const paragraph of String(text).split('\n')) {
    const words = paragraph.split(/\s+/).filter(Boolean);
    if (!words.length) {
      lines += 1;
      continue;
    }
    let current = 0;
    let paragraphLines = 1;
    for (const word of words) {
      const len = word.length;
      if (len > limit) {
        // Long unbreakable word: wraps by character.
        if (current > 0) paragraphLines += 1;
        paragraphLines += Math.ceil(len / limit) - 1;
        current = len % limit || limit;
        continue;
      }
      if (current === 0) current = len;
      else if (current + 1 + len <= limit) current += 1 + len;
      else {
        paragraphLines += 1;
        current = len;
      }
    }
    lines += paragraphLines;
  }
  return lines;
}

function plainText(content) {
  if (typeof content?.text === 'string') return content.text;
  if (Array.isArray(content?.runs)) return content.runs.map((r) => String(r?.text || r?.t || '')).join('');
  return '';
}

function fitFontSize(content, placement, canvasWidth) {
  const text = plainText(content).trim();
  const fontSize = Number(content?.fontSize);
  const width = Number(placement?.width);
  const height = Number(placement?.height);
  if (!text || !(fontSize > 0) || !(width > 0) || !(height > 20)) return null;

  const scale = Math.max(canvasWidth, 320) / FONT_REF_WIDTH;
  const padY = Number(content?.padding) || 0;
  const padX = content?.paddingX != null ? Number(content.paddingX) || 0 : padY;
  const innerW = Math.max(1, width - padX * 2);
  const innerH = Math.max(1, height - padY * 2);
  const lineHeight = Number(content?.lineHeight) > 0 ? Number(content.lineHeight) : 1.25;
  const singleLine = content?.wrap === 'nowrap';
  const charEm = avgCharWidthEm(content);
  const minSize = Math.max(MIN_FONT_PX, Math.round(fontSize * MIN_FONT_RATIO));

  const fits = (size) => {
    const px = size * scale;
    const charsPerLine = innerW / (px * charEm);
    const lines = singleLine ? 1 : estimateLineCount(text, charsPerLine);
    const widthOk = !singleLine || text.length <= charsPerLine;
    return widthOk && lines * px * lineHeight <= innerH;
  };

  let size = fontSize;
  while (size > minSize && !fits(size)) {
    size = Math.max(minSize, size - Math.max(1, Math.round(size * 0.04)));
  }
  size = Math.round(size);
  return size < fontSize ? size : null;
}

/**
 * @param {{ elements?: object[] }} doc canvas elements doc
 * @param {{ width?: number }} [canvas]
 */
function fitTextElementsToBoxes(doc, canvas = {}) {
  if (!doc || !Array.isArray(doc.elements)) return doc;
  const canvasWidth = Number(canvas.width) || Number(doc.canvas?.width) || 1920;
  const canvasHeight = Number(canvas.height) || Number(doc.canvas?.height) || 1080;
  let changed = false;
  const elements = doc.elements.map((el) => {
    if (!el || (el.type !== 'text' && el.type !== 'textbox')) return el;
    let next = el;

    // Pull text boxes that hang off the slide edge back inside it (no resize, so wrap is unchanged).
    const p = el.placement;
    if (p && Number(p.width) > 0 && Number(p.width) <= canvasWidth && !Number(p.rotation)) {
      const x = Math.min(Math.max(Number(p.x) || 0, 0), canvasWidth - Number(p.width));
      const y = Number(p.height) > 0 && Number(p.height) <= canvasHeight
        ? Math.min(Math.max(Number(p.y) || 0, 0), canvasHeight - Number(p.height))
        : Number(p.y) || 0;
      if (Math.round(x) !== Math.round(Number(p.x) || 0) || Math.round(y) !== Math.round(Number(p.y) || 0)) {
        next = { ...next, placement: { ...p, x: Math.round(x), y: Math.round(y) } };
        changed = true;
      }
    }

    const nextSize = fitFontSize(next.content, next.placement, canvasWidth);
    if (nextSize == null) return next;
    changed = true;
    return { ...next, content: { ...next.content, fontSize: nextSize } };
  });
  return changed ? { ...doc, elements } : doc;
}

module.exports = {
  FONT_REF_WIDTH,
  estimateLineCount,
  fitFontSize,
  fitTextElementsToBoxes,
};
