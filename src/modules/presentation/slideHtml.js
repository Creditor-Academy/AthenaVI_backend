/**
 * Shared HTML builders for PPT PDF/PNG export and dashboard slide previews.
 * Kept free of Puppeteer / credit / export-job concerns.
 */

const s3Service = require('../s3/s3.service');
const { downloadRemote } = require('../../shared/utils/downloadRemote');
const { CANVAS_WIDTH, CANVAS_HEIGHT } = require('./presentation.constants');
const { attachPresignedMediaToSlides } = require('./presignSlideMedia');
const {
  cssFromFill,
  slideBackgroundCss,
  textPaintCss,
} = require('./canvasFill');
const { fontCssUrlFromThemeTokens } = require('../../shared/fonts/googleFontsCss');

function bulletsFromContent(content) {
  if (!content || typeof content !== 'object') return [];
  if (Array.isArray(content.bullets)) {
    return content.bullets
      .map((b) => (typeof b === 'string' ? b : b?.text || ''))
      .filter(Boolean);
  }
  return [];
}

async function fetchImageAsBase64(url, s3Key) {
  try {
    if (s3Key) {
      const buffer = await s3Service.getObjectBuffer(s3Key);
      return buffer.toString('base64');
    }
    if (!url || !/^https?:\/\//i.test(String(url))) return null;
    const buffer = await downloadRemote(url, { maxBytes: 12 * 1024 * 1024 });
    return buffer.toString('base64');
  } catch {
    return null;
  }
}

function contentFlipFlags(content = {}) {
  return {
    flipH: content.flipHorizontal === true || content.scaleX === -1,
    flipV: content.flipVertical === true || content.scaleY === -1,
  };
}

function placementTransformCss(placement = {}, content = {}) {
  const rotate = Number(placement.rotation) || 0;
  const { flipH, flipV } = contentFlipFlags(content);
  const parts = [];
  if (rotate) parts.push(`rotate(${rotate}deg)`);
  if (flipH || flipV) parts.push(`scale(${flipH ? -1 : 1}, ${flipV ? -1 : 1})`);
  return parts.length ? parts.join(' ') : 'none';
}

function slideHasElements(slide) {
  return (
    slide?.elements &&
    typeof slide.elements === 'object' &&
    Array.isArray(slide.elements.elements) &&
    slide.elements.elements.length > 0
  );
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function htmlTextInner(c, palette, fallbackColor) {
  const runs = Array.isArray(c.runs) ? c.runs : [];
  if (runs.length) {
    return runs
      .map((run) => {
        const paint = textPaintCss(run.fill || run.color || run.colorRole, palette, fallbackColor);
        return `<span style="${paint}">${escapeHtml(run.text || '')}</span>`;
      })
      .join('');
  }
  const paint = textPaintCss(c.fill || c.color || c.colorRole, palette, fallbackColor);
  return `<span style="${paint}">${escapeHtml(c.text || '')}</span>`;
}

function htmlChartInner(c, palette) {
  const labels = Array.isArray(c.labels) ? c.labels : Array.isArray(c.data?.labels) ? c.data.labels : [];
  const series = Array.isArray(c.series) ? c.series : Array.isArray(c.data?.series) ? c.data.series : [];
  const values = Array.isArray(series[0]?.values)
    ? series[0].values
    : Array.isArray(c.series) && typeof c.series[0] === 'number'
      ? c.series
      : [];
  const colors = Array.isArray(c.colors) && c.colors.length ? c.colors : [palette.primary || '#64748b'];
  if (!values.length) {
    return `<div style="width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:#64748b">chart</div>`;
  }
  const max = Math.max(...values.map(Number), 1);
  const bars = values
    .map((v, i) => {
      const fill = cssFromFill(colors[i % colors.length], palette, '#64748b');
      const h = Math.max(8, (Number(v) / max) * 100);
      return `<div style="flex:1;display:flex;flex-direction:column;justify-content:flex-end;height:100%"><div style="height:${h}%;background:${escapeHtml(fill)};border-radius:4px 4px 0 0"></div></div>`;
    })
    .join('');
  const axis = labels.length
    ? `<div style="display:flex;gap:4px;margin-top:4px;font-size:11px;color:#64748b">${labels
        .slice(0, values.length)
        .map((l) => `<div style="flex:1;text-align:center;overflow:hidden">${escapeHtml(l)}</div>`)
        .join('')}</div>`
    : '';
  return `<div style="width:100%;height:100%;display:flex;flex-direction:column;padding:8px;box-sizing:border-box"><div style="flex:1;display:flex;align-items:stretch;gap:6px">${bars}</div>${axis}</div>`;
}

/**
 * Resolve image src for an element — optionally inlined as data URI.
 */
async function resolveImageSrc(content, opts = {}) {
  const url = content?.url || content?.src || null;
  const s3Key = content?.s3Key || opts.imageRef?.s3Key || null;
  if (opts.inlineImages) {
    const b64 = await fetchImageAsBase64(url, s3Key);
    if (b64) return `data:image/jpeg;base64,${b64}`;
  }
  return url || null;
}

/**
 * Build one slide section HTML.
 */
async function buildSlideHtmlPage(slide, palette, opts = {}) {
  const text = palette.text || '#111111';
  const bg = slideBackgroundCss(slide, palette);
  const inlineImages = Boolean(opts.inlineImages);

  if (slideHasElements(slide)) {
    const canvasW = slide.elements.canvas?.width || CANVAS_WIDTH;
    const canvasH = slide.elements.canvas?.height || CANVAS_HEIGHT;
    const sorted = [...(slide.elements.elements || [])].sort(
      (a, b) => (Number(a.layer) || 0) - (Number(b.layer) || 0)
    );

    const parts = [];
    for (const el of sorted) {
      const p = el.placement || {};
      const c = el.content || {};
      const isText = el.type === 'text' || el.type === 'textbox';
      const transformCss = placementTransformCss(p, isText ? {} : c);
      const style = [
        `position:absolute`,
        `left:${Number(p.x) || 0}px`,
        `top:${Number(p.y) || 0}px`,
        `width:${Number(p.width) || 100}px`,
        `height:${Number(p.height) || 100}px`,
        `opacity:${p.opacity != null ? p.opacity : 1}`,
        `transform:${transformCss}`,
        `transform-origin:center center`,
        `box-sizing:border-box`,
        `overflow:${isText ? 'visible' : 'hidden'}`,
      ].join(';');

      if (el.type === 'group') {
        continue;
      }
      if (isText) {
        const fallback = c.color || (c.colorRole && palette[c.colorRole]) || text;
        const ls =
          c.letterSpacing != null ? `letter-spacing:${Number(c.letterSpacing)}em;` : '';
        const lh =
          c.lineHeight != null ? `line-height:${Number(c.lineHeight)};` : 'line-height:1.25;';
        const fontFamily = c.fontFamily
          ? `font-family:${escapeHtml(c.fontFamily)},Arial,sans-serif;`
          : '';
        parts.push(
          `<div style="${style};font-size:${Number(c.fontSize) || 18}px;font-weight:${c.bold || Number(c.fontWeight) >= 600 ? '700' : '400'};text-align:${escapeHtml(c.align || 'left')};white-space:pre-wrap;${ls}${lh}${fontFamily}">${htmlTextInner(c, palette, fallback)}</div>`
        );
        continue;
      }
      if (el.type === 'image' || el.type === 'icon' || el.type === 'graphic') {
        const src = await resolveImageSrc(c, { inlineImages, imageRef: slide.imageRef });
        if (src) {
          parts.push(
            `<img src="${escapeHtml(src)}" alt="" style="${style};object-fit:${escapeHtml(c.fit || 'cover')}" />`
          );
        } else {
          parts.push(
            `<div style="${style};background:#ddd;display:flex;align-items:center;justify-content:center;color:#666;font-size:14px">${escapeHtml(el.type)}</div>`
          );
        }
        continue;
      }
      if (el.type === 'shape') {
        const bgCss = cssFromFill(c.fill, palette, palette.primary || '#0A84FF');
        const radius =
          c.borderRadius != null
            ? `${c.borderRadius}px`
            : String(c.shape || '').toLowerCase() === 'ellipse' ||
                String(c.shape || '').toLowerCase() === 'circle'
              ? '50%'
              : String(c.shape || '').toLowerCase() === 'pill'
                ? '999px'
                : String(c.shape || '').toLowerCase() === 'rounded-rect'
                  ? '16px'
                  : '0';
        const border =
          c.stroke || c.line
            ? `border:${Number(c.strokeWidth) || 2}px solid ${escapeHtml(c.stroke || c.line)}`
            : '';
        parts.push(
          `<div style="${style};background:${escapeHtml(bgCss)};border-radius:${radius};${border}"></div>`
        );
        continue;
      }
      if (el.type === 'embed') {
        const title = escapeHtml(c.title || c.provider || 'Link');
        const url = escapeHtml(c.url || c.src || '');
        parts.push(
          `<div style="${style};background:#F8FAFC;border:1px solid #CBD5E1;padding:12px;color:${escapeHtml(text)};font-size:14px"><strong>${title}</strong><div>${url}</div></div>`
        );
        continue;
      }
      if (el.type === 'chart') {
        parts.push(`<div style="${style}">${htmlChartInner(c, palette)}</div>`);
        continue;
      }
      if (el.type === 'table') {
        parts.push(
          `<div style="${style};background:#f5f5f5;border:1px solid #ccc;display:flex;align-items:center;justify-content:center;color:#666">${escapeHtml(el.type)}</div>`
        );
      }
    }

    return `<section class="slide" style="width:${canvasW}px;height:${canvasH}px;position:relative;background:${escapeHtml(bg)};overflow:hidden">${parts.join('\n')}</section>`;
  }

  const content = slide.content || {};
  const bullets = bulletsFromContent(content)
    .map((b) => `<li>${escapeHtml(b)}</li>`)
    .join('');
  let imageHtml = '';
  if (slide.imageRef?.url || slide.imageRef?.s3Key) {
    const src = await resolveImageSrc(
      { url: slide.imageRef.url, s3Key: slide.imageRef.s3Key },
      { inlineImages }
    );
    if (src) imageHtml = `<img src="${escapeHtml(src)}" alt="" />`;
  }
  return `
    <section class="slide legacy">
      <div class="text">
        <h1>${escapeHtml(content.title || `Slide ${slide.order}`)}</h1>
        ${content.subtitle ? `<h2>${escapeHtml(content.subtitle)}</h2>` : ''}
        ${content.body ? `<p>${escapeHtml(content.body)}</p>` : ''}
        ${bullets ? `<ul>${bullets}</ul>` : ''}
      </div>
      <div class="media">${imageHtml}</div>
    </section>`;
}

/**
 * Full HTML document for one or more slides.
 */
async function buildDeckHtml(deck, opts = {}) {
  const palette = deck.themeTokens?.palette || {};
  const text = palette.text || '#111111';
  let slides = Array.isArray(opts.slides)
    ? [...opts.slides]
    : [...(deck.slides || [])].sort((a, b) => a.order - b.order);
  if (opts.slideId) slides = slides.filter((s) => s.id === opts.slideId);

  slides = await attachPresignedMediaToSlides(slides);

  const pages = [];
  for (const slide of slides) {
    // eslint-disable-next-line no-await-in-loop
    pages.push(await buildSlideHtmlPage(slide, palette, { inlineImages: Boolean(opts.inlineImages) }));
  }

  const fontHref =
    opts.injectFonts !== false ? fontCssUrlFromThemeTokens(deck.themeTokens) : null;
  const fontLink = fontHref
    ? `<link rel="stylesheet" href="${escapeHtml(fontHref)}" />`
    : '';

  const heading = deck.themeTokens?.fonts?.heading || '';
  const body = deck.themeTokens?.fonts?.body || '';
  const fontFamilyCss = [heading, body, 'Arial', 'Helvetica', 'sans-serif']
    .filter(Boolean)
    .map((f) => (f.includes(' ') ? `"${f}"` : f))
    .join(', ');

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  ${fontLink}
  <style>
    @page { size: 13.333in 7.5in; margin: 0; }
    body { margin: 0; font-family: ${fontFamilyCss}; color: ${escapeHtml(text)}; }
    .slide { page-break-after: always; }
    .slide span { background-repeat: no-repeat; }
    .slide.legacy {
      width: 13.333in; height: 7.5in;
      box-sizing: border-box; padding: 0.6in; display: flex; gap: 0.4in;
      background: ${escapeHtml(palette.bg || '#ffffff')};
    }
    .legacy .text { flex: 1; }
    .legacy .media { width: 4.5in; display: flex; align-items: center; justify-content: center; }
    .legacy .media img { max-width: 100%; max-height: 5.5in; object-fit: contain; }
    .legacy h1 { font-size: 36px; margin: 0 0 12px; }
    .legacy h2 { font-size: 20px; margin: 0 0 16px; font-weight: normal; }
    .legacy p, .legacy li { font-size: 18px; line-height: 1.4; }
  </style>
</head>
<body>${pages.join('\n')}</body>
</html>`;
}

module.exports = {
  bulletsFromContent,
  fetchImageAsBase64,
  contentFlipFlags,
  placementTransformCss,
  slideHasElements,
  escapeHtml,
  htmlTextInner,
  htmlChartInner,
  buildSlideHtmlPage,
  buildDeckHtml,
};
