function isFourParaImageLayout(layoutId, schema) {
  const id = String(layoutId || schema?.layout_id || schema?.variant || '').toLowerCase();
  return id === 'four_para_image_v1' || id === 'four_para_image';
}

const FOUR_PARA_IMAGE_DEFAULTS = {
  HEADING: 'Key points',
  BULLET_1: 'We help teams turn complex ideas into clear narratives that drive decisions.',
  BULLET_2: 'Research, design, and storytelling combine so every slide earns attention.',
  BULLET_3: 'Structured messaging keeps stakeholders aligned from kickoff to launch.',
  BULLET_4: 'Measured outcomes show exactly where the story moved the needle.',
};

const GEOM = {
  viewW: 1920,
  viewH: 1080,
  imgX: 1100,
  imgY: 80,
  imgW: 740,
  imgH: 920,
  radius: 36,
  pad: 14,
  textX: 100,
  barY: 120,
  barW: 56,
  barH: 6,
  headingY: 144,
  headingH: 130,
  headingW: 920,
  cardXs: [100, 580],
  cardYs: [320, 640],
  cardW: 440,
  cardH: 290,
  cardR: 24,
  cardPad: 32,
  textTop: 84,
  textH: 180,
};

function cardRects() {
  const out = [];
  GEOM.cardYs.forEach((y) => GEOM.cardXs.forEach((x) => out.push({ x, y })));
  return out;
}

function buildFourParaImageChromeSvg() {
  const { imgX, imgY, imgW, imgH, radius, pad, textX, barY, barW, barH, cardW, cardH, cardR, cardPad } = GEOM;
  const frameX = imgX - pad;
  const frameY = imgY - pad;
  const frameW = imgW + pad * 2;
  const frameH = imgH + pad * 2;
  const frameR = radius + 8;
  const cards = cardRects()
    .map(({ x, y }, i) => `
    <rect x="${x}" y="${y}" width="${cardW}" height="${cardH}" rx="${cardR}" fill="currentColor" opacity="0.06" />
    <rect x="${x + cardPad}" y="${y + 28}" width="52" height="36" rx="18" fill="currentColor" opacity="0.16" />
    <text x="${x + cardPad + 26}" y="${y + 53}" text-anchor="middle" font-size="18" font-weight="800" font-family="system-ui, sans-serif" fill="currentColor">0${i + 1}</text>`)
    .join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="100%" height="100%" preserveAspectRatio="none">
    <defs>
      <filter id="fpiShadow" x="-10%" y="-8%" width="120%" height="124%">
        <feDropShadow dx="0" dy="16" stdDeviation="18" flood-color="#94A3B8" flood-opacity="0.18" />
      </filter>
    </defs>
    <rect x="${frameX}" y="${frameY}" width="${frameW}" height="${frameH}" rx="${frameR}" fill="#FFFFFF" filter="url(#fpiShadow)" />
    <rect x="${textX}" y="${barY}" width="${barW}" height="${barH}" rx="${barH / 2}" fill="currentColor" />
    ${cards}
  </svg>`;
}

function findEl(elements, ids) {
  const set = new Set(ids);
  return (elements || []).find((e) => set.has(String(e.slotId || '').toUpperCase()));
}

function textOf(el, fallback) {
  const txt = el?.content?.text || el?.text;
  if (txt && String(txt).trim()) return String(txt).trim();
  return fallback;
}

function resolveStoredColor(el, fallback) {
  const fill = el?.content?.fill;
  if (typeof fill === 'string' && fill && fill !== 'none' && fill !== 'transparent') return fill;
  if (fill && typeof fill === 'object' && fill.color) return fill.color;
  return fallback;
}

function buildElements({ canvasW, canvasH, headingText, bullets, imageUrl, accent, textColor, mutedColor, prev = {} }) {
  const sx = canvasW / GEOM.viewW;
  const sy = canvasH / GEOM.viewH;
  const scale = Math.min(sx, sy);
  const radius = Math.round(GEOM.radius * scale);

  const bulletEls = cardRects().map(({ x, y }, i) => {
    const slotId = `BULLET_${i + 1}`;
    return {
      id: prev[slotId]?.id || `slot-${slotId}`,
      slotId,
      type: 'text',
      role: 'body',
      layer: 10,
      placement: {
        x: Math.round((x + GEOM.cardPad) * sx),
        y: Math.round((y + GEOM.textTop) * sy),
        width: Math.round((GEOM.cardW - GEOM.cardPad * 2) * sx),
        height: Math.round(GEOM.textH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: bullets[i],
        fontSize: Math.round(19 * scale),
        fontWeight: 400,
        color: mutedColor,
        align: 'left',
        verticalAlign: 'flex-start',
        lineHeight: 1.5,
        clipToSlot: true,
        maxLines: 5,
      },
    };
  });

  return [
    {
      id: prev.IMAGE_CARD_BG?.id || 'slot-IMAGE_CARD_BG',
      slotId: 'IMAGE_CARD_BG',
      type: 'graphic',
      role: 'decoration',
      layer: 2,
      placement: { x: 0, y: 0, width: canvasW, height: canvasH, rotation: 0, opacity: 1 },
      content: {
        svg: buildFourParaImageChromeSvg(),
        preserveAspectRatio: 'none',
        colorMode: 'recolorable',
        fill: accent,
        stroke: accent,
      },
    },
    {
      id: prev.HERO_IMAGE?.id || 'slot-HERO_IMAGE',
      slotId: 'HERO_IMAGE',
      type: 'image',
      role: 'image',
      layer: 6,
      placement: {
        x: Math.round(GEOM.imgX * sx),
        y: Math.round(GEOM.imgY * sy),
        width: Math.round(GEOM.imgW * sx),
        height: Math.round(GEOM.imgH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        ...(imageUrl ? { url: imageUrl, src: imageUrl } : {}),
        fit: 'cover',
        borderRadius: radius,
        alt: '',
      },
    },
    {
      id: prev.HEADING?.id || 'slot-HEADING',
      slotId: 'HEADING',
      type: 'text',
      role: 'heading',
      layer: 10,
      placement: {
        x: Math.round(GEOM.textX * sx),
        y: Math.round(GEOM.headingY * sy),
        width: Math.round(GEOM.headingW * sx),
        height: Math.round(GEOM.headingH * sy),
        rotation: 0,
        opacity: 1,
      },
      content: {
        text: headingText,
        fontSize: Math.round(38 * scale),
        fontWeight: 800,
        color: textColor,
        align: 'left',
        verticalAlign: 'flex-start',
        lineHeight: 1.2,
        clipToSlot: true,
        maxLines: 2,
      },
    },
    ...bulletEls,
  ];
}

function layoutFourParaImage(docOrElements, schema = {}, palette = {}, canvas = {}) {
  const elements = Array.isArray(docOrElements) ? docOrElements : (docOrElements?.elements || []);
  const canvasW = canvas?.width || docOrElements?.canvas?.width || 1920;
  const canvasH = canvas?.height || docOrElements?.canvas?.height || 1080;
  const pal = palette?.primary ? palette : (palette?.palette || palette || {});
  const accent = pal.primary || pal.accent || '#6366F1';
  const textColor = pal.text || '#0F172A';
  const mutedColor = pal.muted || '#475569';
  const headingEl = findEl(elements, ['HEADING', 'TITLE', 'MAIN_TITLE']);
  const bulletEls = [1, 2, 3, 4].map((n) => findEl(elements, [`BULLET_${n}`, `BODY_${n}`]));
  const imageEl = findEl(elements, ['HERO_IMAGE', 'IMAGE']);
  const cardEl = findEl(elements, ['IMAGE_CARD_BG']);
  const out = buildElements({
    canvasW,
    canvasH,
    headingText: textOf(headingEl, FOUR_PARA_IMAGE_DEFAULTS.HEADING),
    bullets: bulletEls.map((el, i) => textOf(el, FOUR_PARA_IMAGE_DEFAULTS[`BULLET_${i + 1}`])),
    imageUrl: imageEl?.content?.url || imageEl?.content?.src || null,
    accent: resolveStoredColor(cardEl, accent),
    textColor,
    mutedColor,
    prev: {
      IMAGE_CARD_BG: cardEl,
      HERO_IMAGE: imageEl,
      HEADING: headingEl,
      BULLET_1: bulletEls[0],
      BULLET_2: bulletEls[1],
      BULLET_3: bulletEls[2],
      BULLET_4: bulletEls[3],
    },
  });
  if (Array.isArray(docOrElements)) return out;
  return { ...docOrElements, elements: out };
}

module.exports = {
  isFourParaImageLayout,
  layoutFourParaImage,
};
