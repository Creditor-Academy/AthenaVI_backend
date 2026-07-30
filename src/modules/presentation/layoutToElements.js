const crypto = require('crypto');
const {
  CANVAS_WIDTH,
  CANVAS_HEIGHT,
} = require('./presentation.constants');

/**
 * Parse region strings like "cols 2-11, rows 4-7" into pixel placement on a 12-col / 12-row grid.
 * @param {string} region
 * @param {{ width?: number, height?: number }} canvas
 */
function regionToPlacement(region, canvas = {}) {
  const width = canvas.width || CANVAS_WIDTH;
  const height = canvas.height || CANVAS_HEIGHT;
  const colW = width / 12;
  const rowH = height / 12;

  const str = String(region || '');
  const cols = str.match(/cols\s+(\d+)\s*-\s*(\d+)/i);
  const rows = str.match(/rows\s+(\d+)\s*-\s*(\d+)/i);

  const c1 = cols ? Math.max(1, Number(cols[1])) : 1;
  const c2 = cols ? Math.max(c1, Number(cols[2])) : 12;
  const r1 = rows ? Math.max(1, Number(rows[1])) : 1;
  const r2 = rows ? Math.max(r1, Number(rows[2])) : 12;

  return {
    x: Math.round((c1 - 1) * colW),
    y: Math.round((r1 - 1) * rowH),
    width: Math.max(40, Math.round((c2 - c1 + 1) * colW)),
    height: Math.max(40, Math.round((r2 - r1 + 1) * rowH)),
    rotation: 0,
    opacity: 1,
  };
}

function newElementId(prefix = 'el') {
  return `${prefix}_${crypto.randomBytes(6).toString('hex')}`;
}

function textForSlot(slotId, content = {}) {
  const id = String(slotId || '').toLowerCase();
  if (id.includes('title') && !id.includes('subtitle')) return content.title || '';
  if (id.includes('subtitle')) return content.subtitle || '';
  if (id.includes('quote')) return content.quote || content.body || '';
  if (id.includes('bullet')) {
    const bullets = Array.isArray(content.bullets)
      ? content.bullets.map((b) => (typeof b === 'string' ? b : b?.text || '')).filter(Boolean)
      : [];
    return bullets.map((b) => `• ${b}`).join('\n');
  }
  if (id.includes('body') || id.includes('text')) return content.body || '';
  if (id === 'accent') return '';
  return content.body || content.title || '';
}

/**
 * Compile a DECK_LAYOUT schema + slide content into freeform canvas elements.
 * @param {object} layoutSchema
 * @param {object} content
 * @param {object|null} imageRef
 * @param {{ width?: number, height?: number }} canvasSize
 */
function layoutSlotsToElements(layoutSchema, content = {}, imageRef = null, canvasSize = {}) {
  const canvas = {
    width: canvasSize.width || CANVAS_WIDTH,
    height: canvasSize.height || CANVAS_HEIGHT,
  };
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  const elements = [];
  let layer = 1;

  for (const slot of slots) {
    const slotId = slot.id || `slot_${layer}`;
    const placement = regionToPlacement(slot.region, canvas);
    const lower = String(slotId).toLowerCase();

    if (lower.includes('image') || lower === 'hero' || slot.fit === 'cover') {
      const url =
        imageRef?.url ||
        imageRef?.s3Url ||
        (Array.isArray(content.imageUrls) ? content.imageUrls[0] : null) ||
        null;
      elements.push({
        id: newElementId('img'),
        type: 'image',
        layer: layer++,
        placement,
        content: {
          url,
          fit: slot.fit || 'cover',
          alt: content.title || '',
        },
        role: lower.includes('image') ? 'image' : slotId,
      });
      continue;
    }

    if (lower === 'accent') {
      elements.push({
        id: newElementId('shp'),
        type: 'shape',
        layer: layer++,
        placement,
        content: {
          shape: 'rect',
          fill: 'primary',
        },
        role: 'accent',
      });
      continue;
    }

    if (lower.includes('chart') || content.chart) {
      elements.push({
        id: newElementId('cht'),
        type: 'chart',
        layer: layer++,
        placement,
        content: {
          chartType: content.chart?.type || 'bar',
          series: content.chart?.series || content.chart?.data || [],
          labels: content.chart?.labels || [],
        },
        role: 'chart',
      });
      continue;
    }

    const text = textForSlot(slotId, content);
    const isTitle = lower.includes('title') && !lower.includes('subtitle');
    elements.push({
      id: newElementId('txt'),
      type: 'text',
      layer: layer++,
      placement,
      content: {
        text: text || (isTitle ? content.title || '' : ''),
        fontSize: isTitle ? 42 : lower.includes('subtitle') ? 24 : 18,
        bold: isTitle,
        align: 'left',
      },
      role: isTitle ? 'title' : lower.includes('subtitle') ? 'subtitle' : lower.includes('bullet') ? 'body' : slotId,
    });
  }

  // Ensure at least title if no slots
  if (elements.length === 0 && (content.title || content.body)) {
    elements.push({
      id: newElementId('txt'),
      type: 'text',
      layer: 1,
      placement: { x: 120, y: 120, width: 1680, height: 160, rotation: 0, opacity: 1 },
      content: { text: content.title || '', fontSize: 42, bold: true, align: 'left' },
      role: 'title',
    });
    if (content.body || (content.bullets && content.bullets.length)) {
      const bodyText =
        content.body ||
        (Array.isArray(content.bullets)
          ? content.bullets.map((b) => `• ${typeof b === 'string' ? b : b?.text || ''}`).join('\n')
          : '');
      elements.push({
        id: newElementId('txt'),
        type: 'text',
        layer: 2,
        placement: { x: 120, y: 320, width: 1680, height: 600, rotation: 0, opacity: 1 },
        content: { text: bodyText, fontSize: 20, bold: false, align: 'left' },
        role: 'body',
      });
    }
  }

  if (content.notes) {
    // notes stay on slide.content; no canvas element
  }

  return {
    version: 1,
    canvas,
    elements,
  };
}

/**
 * Empty canvas for blank slides.
 */
function blankCanvas(opts = {}) {
  const withDefaultText = opts.withDefaultText === true;
  const canvas = { width: CANVAS_WIDTH, height: CANVAS_HEIGHT };
  const elements = [];
  if (withDefaultText) {
    elements.push({
      id: newElementId('txt'),
      type: 'text',
      layer: 1,
      placement: { x: 200, y: 400, width: 1520, height: 120, rotation: 0, opacity: 1 },
      content: { text: 'Double-click to edit', fontSize: 32, bold: false, align: 'center' },
      role: 'title',
    });
  }
  return { version: 1, canvas, elements };
}

module.exports = {
  regionToPlacement,
  layoutSlotsToElements,
  blankCanvas,
  newElementId,
};
