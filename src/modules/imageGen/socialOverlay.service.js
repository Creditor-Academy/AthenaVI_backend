const sharp = require('sharp');
const AppError = require('../../shared/utils/AppError');
const { getOpenAI } = require('../../shared/services/ai');
const { DEFAULT_SLIDE_MODEL } = require('../../shared/services/ai/llm.service');
const logger = require('../../shared/utils/logger');

const DEFAULT_INSETS = Object.freeze({ top: 0.1, right: 0.1, bottom: 0.1, left: 0.1 });
const WIPE_INSTRUCTION = [
  'Remove ALL letters, numbers, captions, watermarks, logos-as-text, fake UI, and labels.',
  'Keep photography, illustration, lighting, and composition.',
  'Fill vacated text areas with matching background. Do not add any new text.',
].join(' ');

function visionModel() {
  return (
    process.env.IMAGE_GEN_VISION_MODEL ||
    process.env.PPT_VISION_MODEL ||
    DEFAULT_SLIDE_MODEL
  );
}

function escapeXml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function trimCopy(value) {
  return value != null ? String(value).trim() : '';
}

function resolveInsets(format) {
  const raw = format?.overlayInsets && typeof format.overlayInsets === 'object' ? format.overlayInsets : {};
  return {
    top: Number.isFinite(raw.top) ? raw.top : DEFAULT_INSETS.top,
    right: Number.isFinite(raw.right) ? raw.right : DEFAULT_INSETS.right,
    bottom: Number.isFinite(raw.bottom) ? raw.bottom : DEFAULT_INSETS.bottom,
    left: Number.isFinite(raw.left) ? raw.left : DEFAULT_INSETS.left,
  };
}

function resolveAlign(format) {
  const align = format?.overlayAlign;
  if (align === 'center-right' || align === 'middle' || align === 'center') return align;
  return 'center';
}

function resolveFillColor(brandPalette) {
  const hex = Array.isArray(brandPalette) ? brandPalette.find((c) => typeof c === 'string' && c.trim()) : null;
  if (!hex) return '#FFFFFF';
  const raw = String(hex).trim();
  if (/^#[0-9A-Fa-f]{6}$/.test(raw)) return raw;
  if (/^[0-9A-Fa-f]{6}$/.test(raw)) return `#${raw}`;
  return '#FFFFFF';
}

function wrapLines(text, maxChars) {
  const words = String(text || '')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (!words.length) return [];
  const limit = Math.max(8, Math.floor(maxChars));
  const lines = [];
  let current = '';
  for (const word of words) {
    const trial = current ? `${current} ${word}` : word;
    if (trial.length > limit && current) {
      lines.push(current);
      current = word;
    } else {
      current = trial;
    }
  }
  if (current) lines.push(current);
  return lines;
}

function textAnchorForAlign(align) {
  if (align === 'center-right') return 'end';
  return 'middle';
}

function xForAlign(box, align) {
  if (align === 'center-right') {
    return Math.round(box.x + box.w * 0.96);
  }
  return Math.round(box.x + box.w / 2);
}

/**
 * Vision: does this PNG contain letters or numbers?
 * Fail-open → treat as no text so overlay still runs.
 */
async function detectHasTextSafe(buffer) {
  try {
    if (!buffer || !Buffer.isBuffer(buffer)) {
      return { hasText: false, skipped: true };
    }
    const openai = getOpenAI();
    const dataUrl = `data:image/png;base64,${buffer.toString('base64')}`;
    const completion = await openai.chat.completions.create({
      model: visionModel(),
      temperature: 0,
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content:
            'You inspect a PNG. Return JSON only: { "hasText": true|false }. hasText is true if any letters, numbers, captions, watermarks, or UI labels are visible. Ignore pure shapes/icons with no glyphs.',
        },
        {
          role: 'user',
          content: [
            { type: 'text', text: 'Does this image contain any readable letters or numbers?' },
            { type: 'image_url', image_url: { url: dataUrl } },
          ],
        },
      ],
    });
    const raw = completion?.choices?.[0]?.message?.content;
    if (!raw) return { hasText: false, skipped: true };
    const parsed = JSON.parse(raw);
    return { hasText: Boolean(parsed.hasText), skipped: false };
  } catch (err) {
    logger.warn('Social overlay hasText QA skipped', { message: err?.message });
    return { hasText: false, skipped: true };
  }
}

function buildOverlaySvg({
  width,
  height,
  headline,
  subheadline,
  insets,
  align,
  fillColor,
}) {
  const box = {
    x: Math.round(width * insets.left),
    y: Math.round(height * insets.top),
    w: Math.round(width * (1 - insets.left - insets.right)),
    h: Math.round(height * (1 - insets.top - insets.bottom)),
  };
  if (box.w < 40 || box.h < 24) {
    throw new AppError('Overlay inset box is too small', 500);
  }

  let headlineSize = Math.min(Math.round(box.h * 0.28), Math.round(box.w * 0.11), 96);
  headlineSize = Math.max(22, headlineSize);
  let subSize = Math.max(14, Math.round(headlineSize * 0.42));

  const avgChar = 0.58;
  let maxChars = Math.max(8, Math.floor(box.w / (headlineSize * avgChar)));
  let headLines = wrapLines(headline, maxChars).slice(0, 3);
  let subLines = wrapLines(subheadline, Math.floor(maxChars * 1.15)).slice(0, 2);

  const lineGap = 1.18;
  const subGap = Math.round(headlineSize * 0.35);
  let blockH =
    headLines.length * headlineSize * lineGap +
    (subLines.length ? subGap + subLines.length * subSize * lineGap : 0);

  while (blockH > box.h * 0.95 && headlineSize > 18) {
    headlineSize -= 2;
    subSize = Math.max(12, Math.round(headlineSize * 0.42));
    maxChars = Math.max(8, Math.floor(box.w / (headlineSize * avgChar)));
    headLines = wrapLines(headline, maxChars).slice(0, 3);
    subLines = wrapLines(subheadline, Math.floor(maxChars * 1.15)).slice(0, 2);
    blockH =
      headLines.length * headlineSize * lineGap +
      (subLines.length ? subGap + subLines.length * subSize * lineGap : 0);
  }

  const anchor = textAnchorForAlign(align);
  const x = xForAlign(box, align);
  const startY = Math.round(box.y + (box.h - blockH) / 2 + headlineSize);
  const padY = Math.round(headlineSize * 0.35);
  const scrimW = Math.min(box.w, Math.round(box.w * 0.98));
  const scrimX = box.x + Math.round((box.w - scrimW) / 2);
  const scrimY = startY - headlineSize - padY;
  const scrimH = Math.round(blockH + padY * 2);
  const fill = escapeXml(fillColor);

  const tspans = [];
  headLines.forEach((line, i) => {
    const y = Math.round(startY + i * headlineSize * lineGap);
    tspans.push(
      `<text x="${x}" y="${y}" text-anchor="${anchor}" font-family="Arial, Helvetica, sans-serif" font-size="${headlineSize}" font-weight="800" fill="${fill}">${escapeXml(line)}</text>`
    );
  });
  subLines.forEach((line, i) => {
    const y = Math.round(
      startY + headLines.length * headlineSize * lineGap + subGap + i * subSize * lineGap
    );
    tspans.push(
      `<text x="${x}" y="${y}" text-anchor="${anchor}" font-family="Arial, Helvetica, sans-serif" font-size="${subSize}" font-weight="600" fill="${fill}" fill-opacity="0.92">${escapeXml(line)}</text>`
    );
  });

  return `<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
  <rect x="${scrimX}" y="${Math.max(0, scrimY)}" width="${scrimW}" height="${Math.min(height - Math.max(0, scrimY), scrimH)}" rx="${Math.round(headlineSize * 0.28)}" fill="#000000" fill-opacity="0.42"/>
  ${tspans.join('\n  ')}
</svg>`;
}

/**
 * Composite headline/subheadline onto a cropped social PNG.
 * @returns {{ buffer: Buffer, composited: boolean, insets: object, align: string }}
 */
async function compositeOverlay({
  buffer,
  format,
  headline,
  subheadline,
  brandPalette,
  width,
  height,
} = {}) {
  const headlineTrim = trimCopy(headline);
  const subTrim = trimCopy(subheadline);
  const insets = resolveInsets(format);
  const align = resolveAlign(format);

  if (!headlineTrim && !subTrim) {
    return { buffer, composited: false, insets, align };
  }
  if (!buffer || !Buffer.isBuffer(buffer)) {
    throw new AppError('Image buffer is required for social overlay', 400);
  }

  const w = width || format?.width;
  const h = height || format?.height;
  if (!w || !h) {
    throw new AppError('Overlay requires format dimensions', 500);
  }

  const svg = buildOverlaySvg({
    width: w,
    height: h,
    headline: headlineTrim,
    subheadline: subTrim,
    insets,
    align,
    fillColor: resolveFillColor(brandPalette),
  });

  const overlayPng = await sharp(Buffer.from(svg)).png().toBuffer();
  const out = await sharp(buffer)
    .resize(w, h, { fit: 'fill' })
    .composite([{ input: overlayPng, top: 0, left: 0 }])
    .png()
    .toBuffer();

  return { buffer: out, composited: true, insets, align };
}

module.exports = {
  detectHasTextSafe,
  compositeOverlay,
  WIPE_INSTRUCTION,
  resolveInsets,
  resolveAlign,
};
