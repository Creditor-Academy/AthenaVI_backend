function isWideImageStatementOverlayLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase();
  return id === 'wide_image_statement_overlay_v1' || id === 'wide_image_statement_overlay';
}

const WIDE_IMAGE_STATEMENT_OVERLAY_DEFAULTS = {
  SUBHEADLINE: 'Subheadline',
  STATEMENT: 'Great work starts with a clear, unforgettable idea.',
};

function buildWideImageStatementOverlaySvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <radialGradient id="wisoVignette" cx="50%" cy="42%" r="72%">
        <stop offset="0%" stop-color="#020617" stop-opacity="0.08" />
        <stop offset="62%" stop-color="#020617" stop-opacity="0.28" />
        <stop offset="100%" stop-color="#020617" stop-opacity="0.72" />
      </radialGradient>
      <linearGradient id="wisoWash" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#020617" stop-opacity="0.18" />
        <stop offset="38%" stop-color="#020617" stop-opacity="0.22" />
        <stop offset="100%" stop-color="#020617" stop-opacity="0.62" />
      </linearGradient>
    </defs>
    <rect width="1920" height="1080" fill="url(#wisoWash)" />
    <rect width="1920" height="1080" fill="url(#wisoVignette)" />
    <rect x="908" y="428" width="104" height="3" rx="1.5" fill="#FFFFFF" fill-opacity="0.92" />
  </svg>`;
}

function findTextFromElements(elements, ids, fallback) {
  for (const id of ids) {
    const el = elements.find((e) => String(e.slotId || '').toUpperCase() === id);
    const txt = el?.content?.text || el?.text;
    if (txt && String(txt).trim()) return String(txt).trim();
  }
  return fallback;
}

function findImageUrl(elements) {
  const el = (elements || []).find((e) => {
    const sid = String(e.slotId || '').toUpperCase();
    return e.type === 'image' || sid === 'BACKGROUND_IMAGE' || sid === 'HERO_IMAGE';
  });
  return el?.content?.url || el?.content?.src || null;
}

function buildElements({ canvasW, canvasH, statementText, subheadlineText, imageUrl }) {
  const sx = canvasW / 1920;
  const sy = canvasH / 1080;
  const scale = Math.min(sx, sy);
  const long = statementText.length > 42 || statementText.split(/\r?\n/).filter(Boolean).length > 1;
  const statementY = long ? Math.round(456 * sy) : Math.round(480 * sy);
  const statementH = long ? Math.round(220 * sy) : Math.round(140 * sy);

  return [
    {
      id: 'slot-BACKGROUND_IMAGE',
      slotId: 'BACKGROUND_IMAGE',
      type: 'image',
      role: 'background',
      layer: 0,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        ...(imageUrl ? { url: imageUrl, src: imageUrl } : {}),
        fit: 'cover',
        alt: '',
      },
    },
    {
      id: 'slot-OVERLAY_SCRIM',
      slotId: 'OVERLAY_SCRIM',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildWideImageStatementOverlaySvg(),
        preserveAspectRatio: 'none',
        colorMode: 'preserve',
      },
    },
    {
      id: 'slot-SUBHEADLINE',
      slotId: 'SUBHEADLINE',
      type: 'text',
      role: 'subheading',
      layer: 10,
      placement: {
        x: Math.round(280 * sx),
        y: Math.round(348 * sy),
        width: Math.round(1360 * sx),
        height: Math.round(44 * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: String(subheadlineText).toUpperCase(),
        fontSize: Math.round(16 * scale),
        fontWeight: 700,
        color: '#FFFFFF',
        align: 'center',
        verticalAlign: 'center',
        letterSpacing: '0.22em',
        lineHeight: 1.2,
        clipToSlot: true,
        maxLines: 1,
      },
    },
    {
      id: 'slot-STATEMENT',
      slotId: 'STATEMENT',
      type: 'text',
      role: 'quote',
      layer: 10,
      placement: {
        x: Math.round(200 * sx),
        y: statementY,
        width: Math.round(1520 * sx),
        height: statementH,
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: statementText,
        fontSize: Math.round(long ? 46 * scale : 54 * scale),
        fontWeight: 800,
        color: '#FFFFFF',
        align: 'center',
        verticalAlign: 'flex-start',
        lineHeight: 1.18,
        wrap: 'pre-wrap',
        clipToSlot: true,
        maxLines: 3,
      },
    },
  ];
}

function layoutWideImageStatementOverlay(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920;
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080;
  const statementText = findTextFromElements(
    elements,
    ['STATEMENT', 'HEADING', 'MAIN_TITLE', 'QUOTE'],
    WIDE_IMAGE_STATEMENT_OVERLAY_DEFAULTS.STATEMENT
  );
  const subheadlineText = findTextFromElements(
    elements,
    ['SUBHEADLINE', 'SUBTITLE', 'EYEBROW'],
    WIDE_IMAGE_STATEMENT_OVERLAY_DEFAULTS.SUBHEADLINE
  );
  const imageUrl = findImageUrl(elements);
  const out = buildElements({ canvasW, canvasH, statementText, subheadlineText, imageUrl });
  if (Array.isArray(docOrElements)) return out;
  return { ...docOrElements, elements: out };
}

module.exports = {
  isWideImageStatementOverlayLayout,
  buildWideImageStatementOverlaySvg,
  layoutWideImageStatementOverlay,
};
