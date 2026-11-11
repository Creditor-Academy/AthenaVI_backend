const { normalizeCrop } = require('./imageCrop');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const logger = require('../../shared/utils/logger');
const presentationDao = require('./presentation.dao');
const presentationCredit = require('./presentationCredit.service');
const { loadPresentationDeck } = require('./deckGeneration.service');
const s3Service = require('../s3/s3.service');
const inboxService = require('../inbox/inbox.service');
const { PPT_FEATURE } = require('../../shared/config/presentationCreditPricing');
const {
  CANVAS_WIDTH,
  CANVAS_HEIGHT,
  PPTX_WIDTH_IN,
  PPTX_HEIGHT_IN,
  resolveAspectCanvas,
} = require('./presentation.constants');
const { firstHexFromFill } = require('./canvasFill');
const {
  bulletsFromContent,
  fetchImageForPptx,
  imageBufferToPptxImage,
  svgMarkupToPngBuffer,
  graphicTintColor,
  contentFlipFlags,
  slideHasElements,
  buildDeckHtml,
} = require('./slideHtml');
const { FONT_REF_WIDTH } = require('./textFit.util');
const { elementEffectPptxShadow, normalizeElementEffect } = require('./elementEffects');
const { buildPptxText, stagePxToPoints } = require('./pptxText');
const { parseColor, hex6 } = require('./pptxColor');
const { editorChartSpec, pptxChartArgs } = require('./pptxChart');
const { buildPptxTable } = require('./pptxTable');
const { parsePolygonClipPath, custGeomPoints, dashTypeFor } = require('./pptxShapes');
const JSZip = require('jszip');
const { PptxPatches, applyPptxPatchesToZip } = require('./pptxXmlPatches');
const { primaryFamily, embedPptxFonts, fontEmbeddingEnabled } = require('./pptxFonts');
const { isGradientFill, normalizeTarget } = require('./pptxCapability');
const exportRenderer = require('./exportRenderer.service');
const { enrichDeckMediaKeysForExport, inlineGraphicSvgsForExport, s3UrlKey } = require('./presignSlideMedia');
const { parseCssColor, compositeRgbaOnHex } = require('./theme.service');
const { withExportPage, setContentAndSettle } = require('../../shared/utils/exportBrowser');
const {
  isBrowserExportFormat,
  createSemaphore,
  withHeartbeat,
  pdfRenderTimeoutMs,
  safeExportFilename,
  exportFileExt,
  slideImageFilename,
  normalizeExportError,
} = require('./exportJob.util');

const PRESIGN_EXPIRES_SEC = 3600;
const EXPORT_MAX_QUEUED_MS =
  Number(process.env.PPT_EXPORT_MAX_QUEUED_MS) > 0
    ? Number(process.env.PPT_EXPORT_MAX_QUEUED_MS)
    : 5 * 60 * 1000;
const EXPORT_MAX_RENDERING_MS =
  Number(process.env.PPT_EXPORT_MAX_RENDERING_MS) > 0
    ? Number(process.env.PPT_EXPORT_MAX_RENDERING_MS)
    : 45 * 60 * 1000;
/** No heartbeat refresh while RENDERING → treat job as stuck (worker died). */
const EXPORT_RENDERING_HEARTBEAT_STALE_MS =
  Number(process.env.PPT_EXPORT_HEARTBEAT_STALE_MS) > 0
    ? Number(process.env.PPT_EXPORT_HEARTBEAT_STALE_MS)
    : 5 * 60 * 1000;
const PUPPETEER_EXPORT_TIMEOUT_MS =
  Number(process.env.PPT_EXPORT_PUPPETEER_TIMEOUT_MS) > 0
    ? Number(process.env.PPT_EXPORT_PUPPETEER_TIMEOUT_MS)
    : 180_000;
/** Browser exports (PDF / PNG / JPEG) running at once on this server; the rest wait QUEUED. */
const EXPORT_MAX_CONCURRENT_BROWSER =
  Number(process.env.PPT_EXPORT_MAX_CONCURRENT_BROWSER) > 0
    ? Number(process.env.PPT_EXPORT_MAX_CONCURRENT_BROWSER)
    : 2;
const EXPORT_HEARTBEAT_INTERVAL_MS =
  Number(process.env.PPT_EXPORT_HEARTBEAT_INTERVAL_MS) > 0
    ? Number(process.env.PPT_EXPORT_HEARTBEAT_INTERVAL_MS)
    : 20_000;
const browserExportSlots = createSemaphore(EXPORT_MAX_CONCURRENT_BROWSER);

/** Browser exports running / waiting on this server (for /health/export and tests). */
function exportQueueStats() {
  return {
    running: browserExportSlots.active,
    waiting: browserExportSlots.waiting,
    limit: browserExportSlots.limit,
  };
}

function exportJobIsStale(row) {
  if (!row || (row.status !== 'QUEUED' && row.status !== 'RENDERING')) return false;
  const now = Date.now();
  const createdAt = row.createdAt ? new Date(row.createdAt).getTime() : now;
  const updatedAt = row.updatedAt ? new Date(row.updatedAt).getTime() : createdAt;

  if (row.status === 'QUEUED') {
    // A job waiting for a free browser slot keeps beating, so judge it by its last beat.
    return now - updatedAt > EXPORT_MAX_QUEUED_MS;
  }
  if (now - createdAt > EXPORT_MAX_RENDERING_MS) {
    return true;
  }
  return now - updatedAt > EXPORT_RENDERING_HEARTBEAT_STALE_MS;
}

async function touchExportHeartbeat(exportId) {
  if (!exportId) return;
  try {
    await presentationDao.updateExport(exportId, { error: null });
  } catch {
    // non-fatal
  }
}

async function notifyExportFinished({
  userId,
  workspaceId,
  projectId,
  deckId,
  exportId,
  format,
  status,
  projectName,
  error,
}) {
  try {
    const ok = status === 'READY';
    await inboxService.notifyUser({
      userId,
      type: ok ? 'PRESENTATION_EXPORT_COMPLETED' : 'PRESENTATION_EXPORT_FAILED',
      referenceId: exportId,
      workspaceId,
      title: ok ? 'Presentation export ready' : 'Presentation export failed',
      message: ok
        ? `"${projectName || 'Presentation'}" ${format} export is ready.`
        : `"${projectName || 'Presentation'}" ${format} export failed${error ? `: ${error}` : '.'}`,
      metadata: {
        workspaceId,
        projectId,
        deckId,
        exportId,
        format,
        status,
        actionUrl: `${process.env.FRONTEND_URL || ''}/workspaces/${workspaceId}/presentations/${projectId}`,
      },
    });
  } catch (notifyErr) {
    logger.error?.('presentation_export_notify_failed', notifyErr) ||
      console.error('presentation export notify failed', notifyErr);
  }
}

const DEFAULT_SLIDE_SIZE_IN = { w: PPTX_WIDTH_IN, h: PPTX_HEIGHT_IN };

function readPlacementMetrics(placement = {}) {
  return {
    x: Number(placement.x) || 0,
    y: Number(placement.y) || 0,
    width: Number(placement.width ?? placement.w) || 100,
    height: Number(placement.height ?? placement.h) || 100,
  };
}

function pxToIn(x, y, w, h, canvasW = CANVAS_WIDTH, canvasH = CANVAS_HEIGHT, slideSize = DEFAULT_SLIDE_SIZE_IN) {
  return {
    x: (Number(x) || 0) / canvasW * slideSize.w,
    y: (Number(y) || 0) / canvasH * slideSize.h,
    w: Math.max(0.1, (Number(w) || 100) / canvasW * slideSize.w),
    h: Math.max(0.1, (Number(h) || 100) / canvasH * slideSize.h),
  };
}

function placementToIn(placement, canvasW, canvasH, slideSize) {
  const m = readPlacementMetrics(placement);
  return pxToIn(m.x, m.y, m.width, m.height, canvasW, canvasH, slideSize);
}

/**
 * pptxgenjs only accepts 6-digit hex and silently swaps anything else for black, so
 * rgb()/rgba() (palette cardBg / divider, translucent fills) are flattened onto the slide bg.
 */
function toPptxHex(value, palette, fallback) {
  // #RRGGBBAA, #RGB, rgb()/rgba(), hsl(), names… (pptxgenjs turns anything else black).
  const parsed = parseColor(value);
  if (!parsed) return hex6(fallback);
  if (parsed.alpha >= 1) return parsed.hex;
  const rgba = parseCssColor(`#${parsed.hex}`);
  return compositeRgbaOnHex({ ...rgba, a: parsed.alpha }, palette?.bg || '#FFFFFF').replace(/^#/, '').toUpperCase();
}

function resolveColor(value, palette, fallback = '111111') {
  return toPptxHex(resolvePaletteColor(value, palette, fallback), palette, fallback);
}

/**
 * Like resolveColor, but keeps rgba alpha separate so callers can pass it as pptxgenjs
 * `transparency` — overlays (image scrims, translucent text) stay see-through instead of
 * becoming an opaque slab over the photo.
 */
function resolveColorAlpha(value, palette, fallback = '111111') {
  const parsed = parseColor(resolvePaletteColor(value, palette, fallback));
  if (!parsed) return { color: hex6(fallback), alpha: 1 };
  return { color: parsed.hex, alpha: parsed.alpha };
}

/** `transparent`, `none` or a colour with zero alpha. */
function isTransparentColor(value) {
  if (value == null || typeof value !== 'string') return false;
  const raw = value.trim().toLowerCase();
  if (raw === 'transparent' || raw === 'none') return true;
  const rgba = /^rgba?\(/.test(raw) ? parseCssColor(raw) : null;
  if (rgba && rgba.a != null && Number(rgba.a) === 0) return true;
  return /^#[0-9a-f]{8}$/.test(raw) && raw.endsWith('00');
}

/** pptxgenjs `transparency` (0–100) for an alpha; undefined when fully opaque. */
function pptxTransparency(alpha) {
  const a = Math.max(0, Math.min(1, Number(alpha)));
  return a >= 1 ? undefined : Math.round((1 - a) * 100);
}

function withTransparency(props, alpha) {
  const transparency = pptxTransparency(alpha);
  return transparency == null ? props : { ...props, transparency };
}

function resolvePaletteColor(value, palette, fallback) {
  if (!value) return String(fallback).replace(/^#/, '');
  if (typeof value === 'object') return firstHexFromFill(value, palette, fallback);
  const key = String(value);
  if (key === 'primary') return String(palette.primary || palette.text || fallback).replace(/^#/, '');
  if (key === 'secondary') return String(palette.secondary || palette.primary || fallback).replace(/^#/, '');
  if (key === 'accent') return String(palette.accent || palette.primary || fallback).replace(/^#/, '');
  if (key === 'text') return String(palette.text || fallback).replace(/^#/, '');
  if (key === 'textOnImage') {
    return String(palette.textOnImage || palette.onImageText || '#FFFFFF').replace(/^#/, '');
  }
  if (key === 'textOnImageMuted') {
    return String(
      palette.textOnImageMuted || palette.onImageMuted || palette.textOnImage || '#F1F5F9'
    ).replace(/^#/, '');
  }
  if (key === 'muted') return String(palette.muted || palette.text || fallback).replace(/^#/, '');
  if (key === 'bg') return String(palette.bg || 'FFFFFF').replace(/^#/, '');
  if (key === 'surface') return String(palette.surface || palette.bg || 'FFFFFF').replace(/^#/, '');
  if (key === 'divider') return String(palette.divider || palette.muted || 'CCCCCC').replace(/^#/, '');
  if (key === 'cardBg') return String(palette.cardBg || palette.surface || 'F5F5F5').replace(/^#/, '');
  if (key === 'gradientStart') return String(palette.gradientStart || palette.bg || fallback).replace(/^#/, '');
  if (key === 'gradientEnd') return String(palette.gradientEnd || palette.surface || fallback).replace(/^#/, '');
  // rgb()/rgba() literals are flattened to hex by resolveColor
  return key.replace(/^#/, '');
}

/** Long edge of a rasterized graphic: ~150 dpi across a 13.3in slide. */
const SVG_RASTER_MAX_EDGE = 2048;

/**
 * Pixel size for an inline SVG graphic in PPTX: 2× its canvas size (crisp icons), capped so a
 * full-slide graphic isn't drawn at 3840×2160 — that took ~25s per graphic.
 */
function svgRasterSize(placement = {}) {
  const width = (Number(placement.width) || 100) * 2;
  const height = (Number(placement.height) || 100) * 2;
  const k = Math.min(1, SVG_RASTER_MAX_EDGE / Math.max(width, height));
  return { width: Math.round(width * k), height: Math.round(height * k) };
}

/** Light ink reads better than dark below luminance 0.179 (equal contrast with black and white). */
function isDarkHex(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(String(hex || ''));
  if (!m) return false;
  const n = parseInt(m[1], 16);
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b < 0.179;
}

function shapeTypeForPptx(shape) {
  const s = String(shape || 'rect').toLowerCase();
  if (s === 'ellipse' || s === 'oval' || s === 'circle') return 'ellipse';
  if (s === 'line') return 'line';
  if (s === 'triangle') return 'triangle';
  if (s === 'diamond' || s === 'flow-decision') return 'diamond';
  if (s === 'star' || s === 'plus') return 'star5';
  if (s === 'arrow-right' || s === 'right-arrow') return 'rightArrow';
  if (s === 'arrow-left' || s === 'left-arrow') return 'leftArrow';
  if (s === 'arrow-up' || s === 'up-arrow') return 'upArrow';
  if (s === 'arrow-down' || s === 'down-arrow') return 'downArrow';
  // rectRadius only applies to roundRect
  if (s === 'rounded-rect' || s === 'pill') return 'roundRect';
  // flow-process, unknown → rect
  return 'rect';
}

/**
 * An editor gradient fill ({ type: 'gradient', stops: [{ color, at }], angle, kind }) as
 * patch input: resolved stop colours (palette roles, rgba alpha), the CSS angle (editor
 * default 135°), radial or not. Mirrors the editor's cssGradientFromFill.
 */
function editorGradient(fill, palette) {
  const raw = Array.isArray(fill?.stops) && fill.stops.length
    ? fill.stops
    : [{ color: fill?.from || fill?.start || palette.gradientStart || '#3B82F6' }, { color: fill?.to || fill?.end || palette.gradientEnd || '#8B5CF6' }];
  const stops = raw.map((stop, i) => {
    const ink = resolveColorAlpha(stop?.color || stop?.colorRole || stop, palette, '94A3B8');
    const offset = stop?.at != null ? stop.at : stop?.offset;
    const at = offset != null ? (Number(offset) <= 1 ? Number(offset) : Number(offset) / 100) : i / Math.max(1, raw.length - 1);
    return { color: ink.color, alpha: ink.alpha, at };
  });
  return {
    stops,
    angle: fill?.angle != null ? Number(fill.angle) : 135,
    radial: fill?.kind === 'radial' || fill?.gradientKind === 'radial',
  };
}

/** The editor's text effects that have a native PPTX form (see pptxCapability). */
function textEffectPatch(content, palette, inkHex, pt) {
  const c = content || {};
  const colorAlpha = (value, fallback) => {
    const ink = resolveColorAlpha(value || fallback, palette, fallback);
    return { color: ink.color, alpha: ink.alpha };
  };
  switch (c.textEffect) {
    case 'shadow': {
      const { color, alpha } = colorAlpha(c.shadowColor, 'rgba(0, 0, 0, 0.45)');
      return {
        shadow: {
          color,
          alpha,
          blurPt: pt(c.shadowBlur != null ? c.shadowBlur : 4),
          distPt: pt(c.shadowOffset != null ? c.shadowOffset : 4),
          angleDeg: c.shadowAngle != null ? c.shadowAngle : 45,
        },
      };
    }
    case 'lift': {
      const i = (c.liftIntensity != null ? c.liftIntensity : 50) / 100;
      const blur = 8 + i * 20;
      return { shadow: { color: '000000', alpha: 0.2 + i * 0.3, blurPt: pt(blur), distPt: pt(blur / 2), angleDeg: 90 } };
    }
    case 'outline':
      return { outline: { widthPt: pt(c.outlineThickness != null ? c.outlineThickness : 2), color: colorAlpha(c.outlineColor, '#000000').color } };
    case 'hollow':
      return {
        outline: { widthPt: pt(c.hollowThickness != null ? c.hollowThickness : 2), color: c.hollowColor ? colorAlpha(c.hollowColor, inkHex).color : inkHex },
        noFill: true,
      };
    case 'neon': {
      const i = (c.neonIntensity != null ? c.neonIntensity : 70) / 100;
      return { glow: { color: c.neonColor ? colorAlpha(c.neonColor, inkHex).color : inkHex, radiusPt: pt(8 + i * 10), alpha: 0.75 } };
    }
    case 'background':
      return { highlight: colorAlpha(c.textBgColor, '#FEF08A').color };
    default:
      return null;
  }
}

/** Element glow / neon as a native PPTX glow (instead of a shadow look-alike). */
function elementGlowPatch(content, palette, pt) {
  const fx = content?.effect && normalizeElementEffect(content.effect);
  if (!fx || (fx.type !== 'glow' && fx.type !== 'neon')) return null;
  const ink = resolveColorAlpha(fx.color, palette, 'FACC15');
  const radiusPx = fx.type === 'glow' ? fx.size : 6 + (fx.intensity / 100) * 8;
  return { kind: 'glow', color: ink.color, radiusPt: pt(radiusPx), alpha: fx.type === 'neon' ? 0.8 : 0.6 };
}

/**
 * The deck's heading and body fonts as the editor resolves them (googleFonts.js
 * themeFontFamilies): Inter when the theme names none.
 */
function editorThemeFonts(themeTokens) {
  const fonts = themeTokens?.fonts || {};
  const pick = (...names) => names.map(primaryFamily).find(Boolean) || null;
  return {
    heading: pick(fonts.heading, fonts.subheading) || 'Inter',
    body: pick(fonts.body, fonts.subheading, fonts.heading) || 'Inter',
  };
}

/**
 * The font a text element is drawn in: what the render page measured, else the editor's own
 * rule (PptCanvasElement): the element's font, else the heading font for title / heading roles
 * and HEADING / TITLE slots, else the body font.
 */
function resolveExportFontFace(content, el, themeFonts = {}, measured = null) {
  const drawn = primaryFamily(measured?.fontFamily);
  if (drawn) return drawn;
  const own = primaryFamily(content.fontFamily);
  if (own) return own;
  const slot = String(el?.slotId || '').toUpperCase();
  const isHeading = el?.role === 'heading' || el?.role === 'title' || slot.includes('HEADING') || slot.includes('TITLE');
  return (isHeading ? themeFonts.heading : themeFonts.body) || themeFonts.body || themeFonts.heading || null;
}

async function addElementsToPptxSlide(
  s,
  slide,
  palette,
  textColor,
  _brandChartColors = [],
  themeFonts = {},
  slideSize = DEFAULT_SLIDE_SIZE_IN,
  pptx = null,
  {
    measuredText = {},
    measuredTables = {},
    pictures = {},
    backgroundIsPicture = false,
    backgroundHex = 'FFFFFF',
    patches = null,
    slideNumber = 1,
    report = null,
  } = {}
) {
  const doc = slide.elements;
  const canvasW = doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = doc.canvas?.height || CANVAS_HEIGHT;
  // borderRadius is editor-stage px (like fontSize), not placement-canvas px.
  const inPerPx = slideSize.w / FONT_REF_WIDTH;
  // Element effects (shadow, glow…) PowerPoint can show, as a shape / picture shadow.
  const effectShadow = (content) =>
    elementEffectPptxShadow(content, { palette, ptPerStagePx: inPerPx * 72 });
  const elements = [...(doc.elements || [])].sort(
    (a, b) => (Number(a.layer) || 0) - (Number(b.layer) || 0)
  );
  // Sizes authored on the 900px editor stage → points / inches on this slide.
  const pt = (px) => stagePxToPoints(px, slideSize.w);
  const inch = (px) => (Number(px) || 0) * inPerPx;
  // XML patches for one object (gradients, glow, text effects): a name pptxgenjs writes, so
  // the patch can find it afterwards.
  const tag = (list) => {
    const wanted = list.filter(Boolean);
    if (!patches || !wanted.length) return {};
    const objectName = patches.name();
    wanted.forEach((patch) => patches.add(slideNumber, { ...patch, name: objectName }));
    return { objectName };
  };
  const count = (kind, key) => {
    if (!report) return;
    report[kind] = report[kind] || {};
    report[kind][key] = (report[kind][key] || 0) + 1;
  };
  // Text drawn as a picture can't be edited: keep it in the speaker notes.
  const picturedText = [];

  for (const el of elements) {
    const box = placementToIn(el.placement, canvasW, canvasH, slideSize);
    const content = el.content || {};
    const rotate = Number(el.placement?.rotation) || 0;
    if (el.type === 'group') continue;
    // Drawn as part of the slide background picture.
    if (
      backgroundIsPicture &&
      (content.useAsBackground || (doc.backgroundImageElementId && el.id === doc.backgroundImageElementId))
    ) {
      continue;
    }
    // Something PowerPoint can't draw natively: the editor's own rendering, as a picture.
    const picture = pictures[el.id];
    const addPicture = () => {
      const b = pxToIn(picture.box.x, picture.box.y, picture.box.width, picture.box.height, canvasW, canvasH, slideSize);
      const link = (el.type === 'embed' || el.type === 'link') && /^https?:\/\//i.test(String(content.url || ''))
        ? { hyperlink: { url: String(content.url), tooltip: content.title || String(content.url) } }
        : {};
      s.addImage({ data: picture.data, x: b.x, y: b.y, w: b.w, h: b.h, ...link });
      count('pictures', picture.reason || el.type);
    };
    if (picture?.data && picture.box && !picture.fallbackOnly) {
      addPicture();
      if ((el.type === 'text' || el.type === 'textbox') && String(content.text || '').trim()) {
        picturedText.push(String(content.text).trim());
      }
      continue;
    }
    // Element opacity (the editor's frame opacity) multiplies every fill and line.
    const elementOpacity = Number.isFinite(Number(el.placement?.opacity)) ? Math.max(0, Math.min(1, Number(el.placement.opacity))) : 1;

    if (el.type === 'text' || el.type === 'textbox') {
      const textInk = resolveColorAlpha(content.color || content.colorRole, palette, textColor);
      // What the editor drew (fit-to-box size, contrast-adjusted colour), when measured.
      const measured = measuredText[el.id] || null;
      // The editor paints text with `fill` only when it is a gradient; a plain `fill` doesn't
      // change the ink (PptCanvasElement textPaintStyle). Treating it as the colour made
      // eyebrows and stats come out in the wrong colour.
      const gradientInk = isGradientFill(content.fill);
      const measuredColor = !gradientInk && /^#?[0-9a-f]{6}$/i.test(String(measured?.color || ''))
        ? String(measured.color).replace(/^#/, '').toUpperCase()
        : null;
      const boxColor =
        measuredColor ||
        (gradientInk ? firstHexFromFill(content.fill, palette, textInk.color) : textInk.color);
      const { runs, options } = buildPptxText({
        content,
        box,
        rotate,
        slideWidthIn: slideSize.w,
        color: boxColor,
        transparency: gradientInk ? pptxTransparency(elementOpacity) : pptxTransparency(textInk.alpha * elementOpacity),
        fontFace: resolveExportFontFace(content, el, themeFonts, measured),
        runColor: (run) => firstHexFromFill(run.fill || run.color || run.colorRole, palette, boxColor),
        measured,
      });
      const effect = textEffectPatch(content, palette, boxColor, pt);
      const gradientText = isGradientFill(content.fill) ? editorGradient(content.fill, palette) : null;
      Object.assign(
        options,
        tag([effect || gradientText ? { kind: 'text', ...(effect || {}), ...(gradientText ? { gradient: gradientText } : {}) } : null])
      );
      s.addText(runs, options);
      count('native', 'text');
    } else if (el.type === 'image' || el.type === 'icon' || el.type === 'graphic') {
      const url = content.url || content.src;
      // The element's own picture first. The slide's hero photo only fills an image element
      // that has no picture of its own — an icon or a linked photo never becomes the hero.
      const key =
        content.s3Key ||
        (url ? s3UrlKey(url) : null) ||
        (!url && el.type === 'image' ? slide.imageRef?.s3Key || null : null);
      // Inline SVG (compiled diagrams/graphics) takes precedence, matching the editor renderer.
      const inlineSvgPng =
        typeof content.svg === 'string' && content.svg.includes('<svg')
          ? await svgMarkupToPngBuffer(content.svg, {
              ...svgRasterSize(el.placement),
              color: graphicTintColor(content, palette),
            })
          : null;
      // A crop stays a real PowerPoint crop (re-croppable): the whole photo is embedded.
      const crop = el.type === 'image' && !inlineSvgPng ? normalizeCrop(content.crop) : null;
      const image = inlineSvgPng
        ? await imageBufferToPptxImage(inlineSvgPng)
        : await fetchImageForPptx(url, key);
      if (image) {
        const { flipH, flipV } = contentFlipFlags(content);
        const imageOpts = {
          data: image.data,
          x: box.x,
          y: box.y,
          w: box.w,
          h: box.h,
          rotate,
          flipH,
          flipV,
        };
        // Editor renders photos with object-fit: cover (default) — crop instead of stretching.
        const fit = String(content.fit || (inlineSvgPng ? 'contain' : 'cover')).toLowerCase();
        if (crop) {
          // The editor stretches the crop region to the element box: so does srcRect. The image
          // is given its full size, of which the crop region is exactly the box.
          const fullW = box.w / crop.width;
          const fullH = box.h / crop.height;
          imageOpts.w = fullW;
          imageOpts.h = fullH;
          imageOpts.sizing = { type: 'crop', x: crop.x * fullW, y: crop.y * fullH, w: box.w, h: box.h };
        } else if (fit === 'cover' && image.width && image.height) {
          imageOpts.h = box.w * (image.height / image.width);
          imageOpts.sizing = { type: 'cover', w: box.w, h: box.h };
        } else if (fit === 'contain' && image.width && image.height) {
          // Letterbox like CSS object-fit: contain — never stretch (logos must keep proportions).
          const scale = Math.min(box.w / image.width, box.h / image.height);
          imageOpts.w = image.width * scale;
          imageOpts.h = image.height * scale;
          imageOpts.x = box.x + (box.w - imageOpts.w) / 2;
          imageOpts.y = box.y + (box.h - imageOpts.h) / 2;
        }
        if (elementOpacity < 1) imageOpts.transparency = Math.round((1 - elementOpacity) * 100);
        const glow = elementGlowPatch(content, palette, pt);
        const shadow = glow ? null : effectShadow(content);
        if (shadow) imageOpts.shadow = shadow;
        Object.assign(imageOpts, tag([glow]));
        s.addImage(imageOpts);
        count('native', el.type);
      } else {
        // The picture couldn't be loaded: the editor shows nothing there (a broken image), so
        // neither does the export — a grey "image" box used to cover the slide's content.
        logger.warn?.('pptx_image_unavailable', { slideId: slide.id, elementId: el.id, type: el.type });
        count('missing', el.type);
      }
    } else if (el.type === 'shape') {
      // Library shapes cut with a clip-path polygon → native custom geometry.
      const polygon = content.clipPath ? parsePolygonClipPath(content.clipPath) : null;
      let shape = polygon ? (pptx?.ShapeType?.custGeom || 'custGeom') : shapeTypeForPptx(content.shape);
      // The editor rounds any rectangle with a border radius (AI layouts store shape: 'rect' +
      // borderRadius). PowerPoint only rounds a roundRect, so those came out square.
      if (shape === 'rect' && Number(content.borderRadius) > 0) shape = 'roundRect';
      const strokeColor = isTransparentColor(content.stroke || content.line) ? null : content.stroke || content.line;
      // Stroke widths are editor-stage px, like font sizes.
      const strokeWidth = content.strokeWidth != null ? Number(content.strokeWidth) : strokeColor ? 1.5 : 0;
      const dashType = dashTypeFor(content.borderStyle);
      const shapeOpts = {
        x: box.x,
        y: box.y,
        w: box.w,
        h: box.h,
        line: strokeColor
          ? (() => {
              const ink = resolveColorAlpha(strokeColor, palette, 'E5E5E5');
              return withTransparency(
                { color: ink.color, width: Math.max(0.25, pt(strokeWidth || 1.5)), ...(dashType ? { dashType } : {}) },
                ink.alpha * elementOpacity
              );
            })()
          : { type: 'none' },
        rotate,
        ...(polygon ? { points: custGeomPoints(polygon, box) } : {}),
      };
      if (!polygon && (content.borderRadius != null || content.shape === 'rounded-rect' || content.shape === 'pill')) {
        // pptxgenjs rectRadius is in inches, capped at half the shorter side.
        const maxRadius = Math.min(box.w, box.h) / 2;
        const r = Number(content.borderRadius);
        shapeOpts.rectRadius =
          content.shape === 'pill' ? maxRadius : Math.min(maxRadius, (Number.isFinite(r) ? r : 16) * inPerPx);
      }
      const shapeOpacity = (Number.isFinite(Number(content.opacity)) ? Number(content.opacity) : 1) * elementOpacity;
      let gradient = null;
      if (isGradientFill(content.fill)) {
        // pptxgenjs has no gradient fill: write the first colour, then swap in a native
        // <a:gradFill> after the file is written (pptxXmlPatches).
        gradient = editorGradient(content.fill, palette);
        if (shapeOpacity < 1) gradient.stops = gradient.stops.map((st) => ({ ...st, alpha: (st.alpha ?? 1) * shapeOpacity }));
        shapeOpts.fill = { color: gradient.stops[0].color };
      } else {
        // Editor paints rgba fills and multiplies content.opacity on top — mirror both.
        const fill = content.fill;
        const fillSource = fill && typeof fill === 'object' ? fill.color || fill.colorRole : fill;
        // Outlined shapes have a transparent fill: no fill at all (pptxgenjs writes <a:noFill/>),
        // otherwise pptxgenjs swaps the unknown colour for black.
        if (!isTransparentColor(fillSource)) {
          const ink = resolveColorAlpha(fillSource, palette, '0A84FF');
          shapeOpts.fill = withTransparency({ color: ink.color }, ink.alpha * shapeOpacity);
        }
      }
      const glow = elementGlowPatch(content, palette, pt);
      const shadow = glow ? null : effectShadow(content);
      if (shadow) shapeOpts.shadow = shadow;
      Object.assign(shapeOpts, tag([gradient ? { kind: 'shapeGradient', gradient } : null, glow]));
      try {
        s.addShape(shape, shapeOpts);
      } catch {
        s.addShape('rect', { ...shapeOpts, points: undefined });
      }
      count('native', polygon ? 'custom shape' : 'shape');
    } else if (el.type === 'chart') {
      // Drawn like the editor's chart (PptChartRenderer): first series, its colours and labels.
      const spec = editorChartSpec(content, palette);
      if (spec.kind === 'kpi') {
        s.addText(
          [
            { text: spec.kpi.value, options: { fontSize: pt(32), bold: true, color: String(spec.colors[0]).replace(/^#/, ''), breakLine: true } },
            { text: spec.kpi.label, options: { fontSize: pt(12), color: isDarkHex(backgroundHex) ? 'CBD5E1' : '64748B' } },
          ],
          { x: box.x, y: box.y, w: box.w, h: box.h, align: 'center', valign: 'middle', margin: [0, 0, 0, 0], rotate, ...(themeFonts.body ? { fontFace: themeFonts.body } : {}) }
        );
        count('native', 'kpi');
      } else {
        try {
          const args = pptxChartArgs(spec, pptx, box, { pt, dark: isDarkHex(backgroundHex), fontFace: themeFonts.body || null });
          if (args.combo) s.addChart(args.combo, args.options);
          else s.addChart(args.type, args.data, args.options);
          count('native', `chart ${spec.kind}`);
        } catch (chartErr) {
          logger.warn?.('pptx_chart_export_failed', { slideId: slide.id, error: chartErr?.message || chartErr });
          if (picture?.data && picture.box) {
            // The editor's chart as a picture, never an empty "Chart" box.
            addPicture();
          } else {
            s.addText('Chart', { x: box.x, y: box.y, w: box.w, h: box.h, fontSize: 14, color: textColor, align: 'center', valign: 'middle' });
          }
        }
      }
    } else if (el.type === 'table') {
      // The editor's table card and grid, from the render page's measurement when there is one.
      const stageScale = FONT_REF_WIDTH / canvasW;
      const table = buildPptxTable({
        content,
        box,
        measured: measuredTables[el.id] || null,
        inch,
        pt,
        stageW: (Number(el.placement?.width) || 100) * stageScale,
        stageH: (Number(el.placement?.height) || 100) * stageScale,
        fontFace: themeFonts.body || null,
      });
      if (table) {
        if (table.card) s.addShape(pptx?.ShapeType?.roundRect || 'roundRect', table.card);
        s.addTable(table.rows, table.options);
        count('native', 'table');
      } else {
        s.addText('Table', { x: box.x, y: box.y, w: box.w, h: box.h, fontSize: 14, color: '666666', align: 'center', valign: 'middle' });
      }
    } else if (el.type === 'embed') {
      const title = content.title || content.provider || 'Link';
      const url = content.url || content.src || '';
      s.addShape('rect', {
        x: box.x,
        y: box.y,
        w: box.w,
        h: box.h,
        fill: { color: 'F8FAFC' },
        line: { color: 'CBD5E1', width: 1 },
      });
      s.addText(`${title}\n${url}`, {
        x: box.x + 0.15,
        y: box.y + 0.15,
        w: Math.max(0.5, box.w - 0.3),
        h: Math.max(0.4, box.h - 0.3),
        fontSize: 14,
        color: textColor,
        align: 'left',
        valign: 'middle',
        hyperlink: url ? { url } : undefined,
      });
    }
  }

  const notes = [slide.content?.notes ? String(slide.content.notes) : '', picturedText.length ? `Text shown as a picture on this slide:\n${picturedText.join('\n')}` : '']
    .filter(Boolean)
    .join('\n\n');
  if (notes) s.addNotes(notes);
}

async function addLegacyToPptxSlide(s, slide, textColor) {
  const content = slide.content || {};
  const title = content.title || `Slide ${slide.order}`;

  s.addText(String(title), {
    x: 0.5,
    y: 0.4,
    w: 8.5,
    h: 0.8,
    fontSize: 28,
    bold: true,
    color: textColor,
  });

  if (content.subtitle) {
    s.addText(String(content.subtitle), {
      x: 0.5,
      y: 1.2,
      w: 8.5,
      h: 0.5,
      fontSize: 16,
      color: textColor,
    });
  }

  const bullets = bulletsFromContent(content);
  if (bullets.length) {
    s.addText(
      bullets.map((t) => ({ text: t, options: { bullet: true, breakLine: true } })),
      {
        x: 0.5,
        y: 1.9,
        w: 7.5,
        h: 4.5,
        fontSize: 16,
        color: textColor,
        valign: 'top',
      }
    );
  } else if (content.body) {
    s.addText(String(content.body), {
      x: 0.5,
      y: 1.9,
      w: 7.5,
      h: 4.5,
      fontSize: 16,
      color: textColor,
      valign: 'top',
    });
  }

  const imageUrl = slide.imageRef?.url;
  const imageKey = slide.imageRef?.s3Key;
  if (imageUrl || imageKey) {
    const image = await fetchImageForPptx(imageUrl, imageKey);
    if (image) {
      s.addImage({
        data: image.data,
        x: 8.4,
        y: 1.6,
        w: 4.4,
        h: 4.4,
      });
    }
  }

  if (content.notes) s.addNotes(String(content.notes));
}

/**
 * @param {object} deck
 * @param {{ slideId?: string, onSlideProcessed?: Function, assets?: object }} opts
 *   assets: what the editor renderer drew (exportRenderer.capturePptxAssets) — textMetrics
 *   (fitted font sizes, colours), pictures for elements PowerPoint can't draw, background
 *   pictures. Without it PPTX uses the stored sizes and native shapes only.
 */
/**
 * The slide ids an export covers, or null for the whole deck. `slideIds` (any set) wins over
 * the older single `slideId`.
 */
function exportSlideIds({ slideId = null, slideIds = null } = {}) {
  if (Array.isArray(slideIds) && slideIds.length) return [...new Set(slideIds.map(String))];
  return slideId ? [String(slideId)] : null;
}

/** The deck's slides an export covers, always in deck order. */
function selectExportSlides(deck, selection = {}) {
  const ordered = [...(deck?.slides || [])].sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
  const ids = exportSlideIds(selection);
  if (!ids) return ordered;
  const wanted = new Set(ids);
  return ordered.filter((s) => wanted.has(s.id));
}

/** Image options from the request, clamped to what the renderers support. */
function imageExportOptions({ scale, quality, transparent, format } = {}) {
  const s = Number(scale);
  const q = Number(quality);
  return {
    scale: [1, 2, 3].includes(s) ? s : 1,
    quality: quality != null && Number.isFinite(q) ? Math.min(100, Math.max(60, Math.round(q))) : 90,
    // JPEG has no transparency.
    transparent: Boolean(transparent) && String(format || '').toUpperCase() === 'PNG',
  };
}

/**
 * @param {object} deck
 * @param {object} [opts]
 * @param {boolean} [opts.embedFonts]  embed the deck's Google Fonts (PowerPoint target); off by
 *   default so tests and offline callers never reach the network.
 */
async function buildPptxBuffer(
  deck,
  { slideId, slideIds, onSlideProcessed, assets = null, report = null, embedFonts = false } = {}
) {
  const textMetrics = assets?.textMetrics || null;
  const tableMetrics = assets?.tableMetrics || {};
  const patches = new PptxPatches();
  let slideNumber = 0;
  const pictures = assets?.pictures || {};
  const backgrounds = assets?.backgrounds || {};
  const PptxGenJS = require('pptxgenjs');
  const pptx = new PptxGenJS();
  const aspect = resolveAspectCanvas(deck.aspectRatio);
  const layoutName = `LAYOUT_${String(deck.aspectRatio || '16:9').replace(':', 'x')}`;
  pptx.defineLayout({
    name: layoutName,
    width: aspect.pptxWidthIn || PPTX_WIDTH_IN,
    height: aspect.pptxHeightIn || PPTX_HEIGHT_IN,
  });
  pptx.layout = layoutName;

  const palette = deck.themeTokens?.palette || {};
  const brandChartColors = deck.themeTokens?.brand?.chartColors || [];
  const themeFonts = editorThemeFonts(deck.themeTokens);
  // The theme's fonts, so text added later in PowerPoint uses the deck's fonts too.
  pptx.theme = { headFontFace: themeFonts.heading, bodyFontFace: themeFonts.body };
  const slides = selectExportSlides(deck, { slideId, slideIds });
  const bgColor = String(palette.bg || 'FFFFFF').replace(/^#/, '');
  const textColor = String(palette.text || '111111').replace(/^#/, '');

  for (const original of slides) {
    slideNumber += 1;
    // Build from the elements the editor drew when the render page reported them.
    const slide = exportRenderer.withStageElements(original, assets?.stageSlides?.[original.id]);
    const slideBg =
      slide.content?.background?.color ||
      slide.elements?.backgroundColor ||
      slide.backgroundColor ||
      palette.bg ||
      'FFFFFF';
    const backgroundPicture = backgrounds[slide.id] || null;
    const s = pptx.addSlide();
    // pptxgenjs ignores a `background` passed to addSlide(): only the setter writes <p:bg>.
    // (Every exported slide used to come out white, whatever its colour in the editor.)
    s.background = backgroundPicture
      ? { data: backgroundPicture, path: 'background.jpg' }
      : { color: resolveColor(slideBg, palette, 'FFFFFF') };
    const bgFill = slide.elements?.backgroundFill || slide.backgroundFill;
    const bgStart = slide.elements?.backgroundGradientStart || slide.backgroundGradientStart;
    const bgEnd = slide.elements?.backgroundGradientEnd || slide.backgroundGradientEnd;
    if (!backgroundPicture && (isGradientFill(bgFill) || (bgStart && bgEnd))) {
      const gradient = editorGradient(
        isGradientFill(bgFill)
          ? bgFill
          : {
              type: 'gradient',
              kind: slide.elements?.backgroundGradientKind || slide.backgroundGradientKind,
              angle: slide.elements?.backgroundGradientAngle ?? slide.backgroundGradientAngle,
              stops: slide.elements?.backgroundGradientStops || [
                { color: bgStart, at: 0 },
                { color: bgEnd, at: 1 },
              ],
            },
        palette
      );
      // Native gradient background (pptxgenjs writes the first colour; the patch swaps it).
      s.background = { color: gradient.stops[0].color };
      patches.add(slideNumber, { kind: 'backgroundGradient', gradient });
    }
    if (slideHasElements(slide)) {
      await addElementsToPptxSlide(
        s,
        slide,
        palette,
        textColor,
        brandChartColors,
        themeFonts,
        {
          w: aspect.pptxWidthIn || PPTX_WIDTH_IN,
          h: aspect.pptxHeightIn || PPTX_HEIGHT_IN,
        },
        pptx,
        {
          measuredText: textMetrics?.[slide.id] || {},
          measuredTables: tableMetrics?.[slide.id] || {},
          pictures: pictures[slide.id] || {},
          backgroundIsPicture: Boolean(backgroundPicture),
          backgroundHex: resolveColor(slideBg, palette, 'FFFFFF'),
          patches,
          slideNumber,
          report,
        }
      );
    } else {
      await addLegacyToPptxSlide(s, slide, textColor);
    }
    if (typeof onSlideProcessed === 'function') {
      // eslint-disable-next-line no-await-in-loop
      await onSlideProcessed(slide);
    }
  }

  const out = await pptx.write({ outputType: 'nodebuffer' });
  const written = Buffer.isBuffer(out) ? out : Buffer.from(out);
  if (report) report.patches = patches.size;
  const wantFonts = embedFonts && fontEmbeddingEnabled();
  if (!patches.size && !wantFonts) return written;
  const zip = await JSZip.loadAsync(written);
  // Gradients, glow and text effects pptxgenjs can't write.
  await applyPptxPatchesToZip(zip, patches);
  if (wantFonts) {
    // The fonts the slides use, inside the file, so PowerPoint wraps text like the editor.
    try {
      const fonts = await embedPptxFonts(zip);
      if (report) report.fonts = fonts;
    } catch (err) {
      logger.warn('pptx_font_embed_failed', { deckId: deck.id, error: String(err?.message || err).slice(0, 300) });
    }
  }
  return zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
}

/**
 * Run `fn` with the editor renderer (export-render page). If the page can't be reached
 * (not deployed, not configured, too old) log it and use `fallback`, so export keeps working.
 */
async function withEditorRenderer(deck, label, fn, fallback) {
  if (!exportRenderer.isRendererEnabled()) return fallback();
  try {
    return await fn();
  } catch (err) {
    if (!(err instanceof exportRenderer.RendererUnavailableError)) throw err;
    logger.warn('export_renderer_unavailable', {
      deckId: deck.id,
      export: label,
      error: String(err.message || err).slice(0, 500),
    });
    return fallback();
  }
}

async function buildPdfBuffer(deck, opts = {}) {
  return withEditorRenderer(
    deck,
    'pdf',
    () => exportRenderer.renderDeckPdf(deck, { slideIds: exportSlideIds(opts) }),
    () => buildPdfBufferLegacy(deck, opts)
  );
}

/** PDF from the server-side HTML renderer (slideHtml.js) — fallback only. */
async function buildPdfBufferLegacy(deck, opts = {}) {
  const aspect = resolveAspectCanvas(deck.aspectRatio);
  const slides = selectExportSlides(deck, opts);
  const slideCount = slides.length;
  // The whole deck loads as one page, so big decks get more time.
  const contentTimeout = pdfRenderTimeoutMs(slideCount, PUPPETEER_EXPORT_TIMEOUT_MS);
  return withExportPage(async (page) => {
    await page.setViewport({ width: aspect.width, height: aspect.height });
    page.setDefaultNavigationTimeout(contentTimeout);
    page.setDefaultTimeout(contentTimeout);
    // Not waitUntil 'networkidle0': it can wait forever with nothing left loading.
    await setContentAndSettle(page, await buildDeckHtml(deck, { ...opts, slideId: null, slides }), {
      timeoutMs: contentTimeout,
    });
    const pdf = await page.pdf({
      width: `${aspect.pptxWidthIn}in`,
      height: `${aspect.pptxHeightIn}in`,
      // Slides are laid out in canvas px; scale them to exactly fill the page (96 CSS px per inch).
      scale: (aspect.pptxWidthIn * 96) / aspect.width,
      printBackground: true,
      margin: { top: 0, right: 0, bottom: 0, left: 0 },
    });
    return Buffer.from(pdf);
  });
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (let i = 0; i < buffer.length; i += 1) {
    crc = CRC32_TABLE[(crc ^ buffer[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** Date / time in the ZIP (MS-DOS) format. */
function dosDateTime(date = new Date()) {
  const time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
  const day = ((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  return { time, day };
}

/**
 * Minimal ZIP (store only) for multi-slide raster exports. Each entry carries its real CRC32:
 * Windows Explorer and macOS Archive Utility refuse entries whose checksum doesn't match.
 */
function buildZipBuffer(files) {
  const parts = [];
  const central = [];
  let offset = 0;
  const stamp = dosDateTime();

  function u16(n) {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n, 0);
    return b;
  }
  function u32(n) {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0, 0);
    return b;
  }

  for (const file of files) {
    const name = Buffer.from(file.name, 'utf8');
    const data = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data);
    const checksum = crc32(data);
    const local = Buffer.concat([
      u32(0x04034b50),
      u16(20),
      u16(0x0800), // file names are UTF-8
      u16(0), // stored
      u16(stamp.time),
      u16(stamp.day),
      u32(checksum),
      u32(data.length),
      u32(data.length),
      u16(name.length),
      u16(0),
      name,
      data,
    ]);
    parts.push(local);
    central.push(
      Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0x0800),
        u16(0),
        u16(stamp.time),
        u16(stamp.day),
        u32(checksum),
        u32(data.length),
        u32(data.length),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(offset),
        name,
      ])
    );
    offset += local.length;
  }

  const centralBuf = Buffer.concat(central);
  const end = Buffer.concat([
    u32(0x06054b50),
    u16(0),
    u16(0),
    u16(files.length),
    u16(files.length),
    u32(centralBuf.length),
    u32(offset),
    u16(0),
  ]);

  return Buffer.concat([...parts, centralBuf, end]);
}

async function buildRasterExport(
  deck,
  { format, slideId, slideIds, deckName, onSlideProcessed, scale, quality, transparent } = {}
) {
  const type = String(format || 'PNG').toUpperCase() === 'JPEG' ? 'jpeg' : 'png';
  const ext = type === 'jpeg' ? 'jpg' : 'png';
  const image = imageExportOptions({ scale, quality, transparent, format: type === 'jpeg' ? 'JPEG' : 'PNG' });
  const ordered = selectExportSlides(deck);
  const slides = selectExportSlides(deck, { slideId, slideIds });
  if (!slides.length) throw new AppError('No slides to export', 400);

  // Files are numbered by the slide's place in the deck: <Deck>-slide-03.png.
  const position = new Map(ordered.map((s, i) => [s.id, i + 1]));
  const nameFor = (slideIdValue, i) =>
    slideImageFilename(deckName, position.get(slideIdValue) || i + 1, ext);

  const images = await withEditorRenderer(
    deck,
    type,
    async () => {
      const shots = await exportRenderer.renderDeckImages(deck, {
        slideIds: slides.map((s) => s.id),
        format: type,
        scale: image.scale,
        quality: image.quality,
        transparent: image.transparent,
        onSlide: onSlideProcessed,
      });
      return shots.map((shot, i) => ({ name: nameFor(shot.slideId, i), data: shot.data }));
    },
    async () => {
      let firstFailure = null;
      const shots = await renderSlideScreenshots(deck, {
        slides,
        format: type,
        scale: image.scale,
        quality: image.quality,
        onSlideProcessed,
        stopOnFailure: true,
        fileName: (slide, i) => nameFor(slide.id, i),
        onSlide: (image, slide, err) => {
          if (!image && !firstFailure) firstFailure = err || new Error(`Slide ${slide?.id} did not render`);
        },
      });
      if (firstFailure) throw firstFailure;
      return shots;
    }
  );

  // A missing slide must fail the export, not ship a partial (or empty) zip.
  if (images.length !== slides.length) throw new Error('Some slides did not render');

  if (images.length === 1) {
    return {
      buffer: images[0].data,
      contentType: type === 'jpeg' ? 'image/jpeg' : 'image/png',
      ext: type === 'jpeg' ? 'jpg' : 'png',
    };
  }

  return {
    buffer: buildZipBuffer(images),
    contentType: 'application/zip',
    ext: 'zip',
  };
}

/**
 * Render one or more slides to raster buffers with a single Puppeteer browser.
 * Export only — dashboard previews are rendered by the frontend, never screenshotted.
 *
 * @param {object} deck
 * @param {{ slides?: object[], format?: string, onSlide?: Function }} opts
 *   onSlide → optional callback after each slide (upload progressively)
 */
async function renderSlideScreenshots(
  deck,
  {
    slides,
    format = 'jpeg',
    scale = 1,
    quality = 82,
    onSlide,
    onSlideProcessed,
    fileName,
    stopOnFailure = false,
  } = {}
) {
  const type = String(format || 'jpeg').toLowerCase() === 'png' ? 'png' : 'jpeg';
  const list = Array.isArray(slides) && slides.length
    ? slides
    : [...(deck.slides || [])].sort((a, b) => a.order - b.order);
  if (!list.length) return [];

  const contentTimeout = PUPPETEER_EXPORT_TIMEOUT_MS;
  const jpegQuality = Math.min(100, Math.max(1, Math.round(Number(quality) || 82)));
  const deviceScaleFactor = Number(scale) > 0 ? Number(scale) : 1;

  return withExportPage(async (firstPage) => {
    const browser = firstPage.browser();
    const images = [];
    for (let i = 0; i < list.length; i += 1) {
      const slide = list[i];
      const canvasW = Math.max(320, Math.round(slide.elements?.canvas?.width || CANVAS_WIDTH));
      const canvasH = Math.max(180, Math.round(slide.elements?.canvas?.height || CANVAS_HEIGHT));
      // A fresh page per slide (a second setContent on the same page could hang).
      const page = i === 0 ? firstPage : await browser.newPage();
      // Don't let a single broken remote image hang forever.
      page.setDefaultNavigationTimeout(contentTimeout);
      page.setDefaultTimeout(contentTimeout);
      let failed = false;
      try {
        // eslint-disable-next-line no-await-in-loop
        await page.setViewport({ width: canvasW, height: canvasH, deviceScaleFactor });
        // eslint-disable-next-line no-await-in-loop
        await setContentAndSettle(page, await buildDeckHtml({ ...deck, slides: [slide] }), {
          timeoutMs: contentTimeout,
        });
        // eslint-disable-next-line no-await-in-loop
        const buf = await page.screenshot({
          type,
          quality: type === 'jpeg' ? jpegQuality : undefined,
          fullPage: false,
        });
        const image = {
          slideId: slide.id,
          order: slide.order,
          name:
            typeof fileName === 'function'
              ? fileName(slide, i)
              : `slide-${String(i + 1).padStart(2, '0')}.${type === 'jpeg' ? 'jpg' : 'png'}`,
          data: Buffer.from(buf),
        };
        images.push(image);
        if (typeof onSlide === 'function') {
          // eslint-disable-next-line no-await-in-loop
          await onSlide(image, slide);
        }
        if (typeof onSlideProcessed === 'function') {
          // eslint-disable-next-line no-await-in-loop
          await onSlideProcessed(slide);
        }
      } catch (err) {
        failed = true;
        logger.warn?.('slide_screenshot_failed', {
          slideId: slide.id,
          error: err.message,
        }) || console.warn('slide screenshot failed', slide.id, err.message);
        if (typeof onSlide === 'function') {
          // eslint-disable-next-line no-await-in-loop
          await onSlide(null, slide, err);
        }
      } finally {
        if (page !== firstPage) {
          await page.close().catch(() => {});
        }
      }
      if (failed && stopOnFailure) break;
    }
    return images;
  });
}

/**
 * What PPTX takes from the editor renderer: fitted font sizes and colours, pictures of the
 * elements PowerPoint can't draw, background pictures. Never fails the export: without it
 * PPTX falls back to stored sizes and native shapes.
 */
async function capturePptxAssets(deck, { slideId, slideIds, target } = {}) {
  if (!exportRenderer.isRendererEnabled()) return null;
  try {
    return await exportRenderer.capturePptxAssets(deck, {
      slideIds: exportSlideIds({ slideId, slideIds }),
      target: normalizeTarget(target),
    });
  } catch (err) {
    logger.warn('pptx_renderer_capture_failed', {
      deckId: deck.id,
      error: String(err?.message || err).slice(0, 500),
    });
    return null;
  }
}

async function processExport({
  exportId,
  workspaceId,
  userId,
  projectId,
  projectName,
  slideId,
  slideIds = null,
  pptxTarget = 'powerpoint',
  image = {},
}) {
  const row = await presentationDao.findExport(exportId);
  if (!row) return;

  const format = String(row.format || '').toUpperCase();
  const heartbeat = () => touchExportHeartbeat(exportId);
  let releaseSlot = null;

  try {
    // PDF / images each start a browser: cap how many run at once so a burst of exports
    // can't exhaust memory. Waiting jobs stay QUEUED and keep beating.
    // PPTX also opens the browser when it measures text with the editor renderer.
    if (isBrowserExportFormat(format) || (format === 'PPTX' && exportRenderer.isRendererEnabled())) {
      releaseSlot = await withHeartbeat(
        heartbeat,
        () => browserExportSlots.acquire(),
        EXPORT_HEARTBEAT_INTERVAL_MS
      );
    }

    await presentationDao.updateExport(exportId, { status: 'RENDERING' });
    const deckRaw = await presentationDao.findDeckById(row.deckId);
    if (!deckRaw) {
      throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
    }
    // Stable S3 keys for media (stored links expire), and library SVG graphics inlined so
    // every renderer can draw and tint them without fetching.
    const deck = await inlineGraphicSvgsForExport(enrichDeckMediaKeysForExport(deckRaw));

    // Beat throughout: a long PDF render sends no per-slide callbacks.
    const { buffer, contentType, ext } = await withHeartbeat(
      heartbeat,
      async () => {
        if (format === 'PPTX') {
          const assets = await capturePptxAssets(deck, { slideId, slideIds, target: pptxTarget });
          const report = {};
          const pptxBuffer = await buildPptxBuffer(deck, {
            slideId,
            slideIds,
            onSlideProcessed: heartbeat,
            assets,
            report,
            // Google Slides ignores embedded fonts (it uses Google Fonts by name); PowerPoint needs them.
            embedFonts: normalizeTarget(pptxTarget) === 'powerpoint',
          });
          // What became a picture (PowerPoint can't draw it) and what stayed editable.
          logger.info('pptx_export_report', {
            exportId,
            deckId: deck.id,
            target: normalizeTarget(pptxTarget),
            measured: Boolean(assets),
            ...report,
          });
          return {
            buffer: pptxBuffer,
            contentType: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            ext: 'pptx',
          };
        }
        if (format === 'PDF') {
          return {
            buffer: await buildPdfBuffer(deck, { slideId, slideIds }),
            contentType: 'application/pdf',
            ext: 'pdf',
          };
        }
        if (format === 'PNG' || format === 'JPEG') {
          return buildRasterExport(deck, {
            format,
            slideId,
            slideIds,
            deckName: projectName,
            onSlideProcessed: heartbeat,
            ...image,
          });
        }
        throw new AppError(`Unsupported export format: ${format}`, 400);
      },
      EXPORT_HEARTBEAT_INTERVAL_MS
    );
    if (releaseSlot) {
      releaseSlot();
      releaseSlot = null;
    }

    const s3Key = `presentations/${workspaceId}/${deck.id}/exports/${exportId}.${ext}`;
    await s3Service.uploadFileToKey(buffer, s3Key, contentType);

    const chargeResult = await presentationCredit.chargeFlat({
      workspaceId,
      userId,
      feature: PPT_FEATURE.EXPORT,
      idempotencyKey: `ppt:export:${exportId}`,
      metadata: {
        deckId: deck.id,
        exportId,
        format,
        slideId: slideId || null,
        slideCount: selectExportSlides(deck, { slideId, slideIds }).length,
      },
    });

    const creditsCharged = chargeResult.skipped
      ? 0
      : chargeResult.charged || chargeResult.pricing?.athenaCredits || 0;

    if (!chargeResult.skipped && creditsCharged > 0) {
      await presentationDao.incrementDeckCreditsCharged(deck.id, creditsCharged);
    }

    await presentationDao.updateExport(exportId, {
      status: 'READY',
      s3Key,
      creditCharged: !chargeResult.skipped,
      creditsCharged,
      error: null,
    });

    await notifyExportFinished({
      userId,
      workspaceId,
      projectId: projectId || deck.projectId,
      deckId: deck.id,
      exportId,
      format,
      status: 'READY',
      projectName,
    });
  } catch (err) {
    const userMessage = normalizeExportError(err);
    // The technical cause goes to the log; the user sees a plain message.
    logger.error('presentation_export_failed', {
      exportId,
      deckId: row.deckId,
      format,
      slideId: slideId || null,
      slideIds: slideIds || null,
      userMessage,
      error: String(err?.message || err),
      stack: err?.stack,
    });
    try {
      await presentationDao.updateExport(exportId, { status: 'FAILED', error: userMessage });
    } catch (updateErr) {
      logger.error('presentation_export_status_update_failed', {
        exportId,
        error: String(updateErr?.message || updateErr),
      });
    }
    await notifyExportFinished({
      userId,
      workspaceId,
      projectId,
      deckId: row.deckId,
      exportId,
      format: row.format,
      status: 'FAILED',
      projectName,
      error: userMessage,
    });
  } finally {
    if (releaseSlot) releaseSlot();
  }
}

/** The requested slide ids, checked against the deck (404 for one that isn't in it). */
function checkedSlideIds(deck, { slideId = null, slideIds = null } = {}) {
  const ids = exportSlideIds({ slideId, slideIds });
  if (!ids) return null;
  const known = new Set((deck.slides || []).map((s) => s.id));
  if (ids.some((id) => !known.has(id))) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);
  return ids;
}

async function queueExport({
  workspaceId,
  presentationId,
  userId,
  format,
  slideId,
  slideIds,
  pptxTarget,
  scale,
  quality,
  transparent,
}) {
  const { deck, project } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });

  const normalizedFormat = String(format || '').toUpperCase();
  if (!['PPTX', 'PDF', 'PNG', 'JPEG'].includes(normalizedFormat)) {
    throw new AppError('format must be PPTX, PDF, PNG, or JPEG', 400);
  }

  const selectedIds = checkedSlideIds(deck, { slideId, slideIds });
  const image = imageExportOptions({ scale, quality, transparent, format: normalizedFormat });

  const exportAc = presentationCredit.getFlatAc(PPT_FEATURE.EXPORT);
  await presentationCredit.assertAfford(workspaceId, userId, exportAc);

  const exportRow = await presentationDao.createExport({
    deckId: deck.id,
    format: normalizedFormat,
    status: 'QUEUED',
    creditCharged: false,
  });

  setImmediate(() => {
    processExport({
      exportId: exportRow.id,
      workspaceId,
      userId,
      projectId: project.id,
      projectName: project.name,
      // One slide keeps the single-slide id too (logs, credit metadata).
      slideId: selectedIds && selectedIds.length === 1 ? selectedIds[0] : null,
      slideIds: selectedIds,
      pptxTarget: normalizeTarget(pptxTarget),
      image,
    });
  });

  return {
    exportId: exportRow.id,
    format: normalizedFormat,
    status: 'QUEUED',
    estimatedCredits: exportAc,
    slideId: selectedIds && selectedIds.length === 1 ? selectedIds[0] : null,
    slideIds: selectedIds,
  };
}

/**
 * Slide images made in the browser cost the same flat export fee as a server export, charged
 * once per download (`downloadId`, chosen by the browser, makes a retried request free).
 */
async function chargeBrowserExport({ workspaceId, presentationId, userId, format, slideIds, downloadId }) {
  const { deck } = await loadPresentationDeck(presentationId, { requireWorkspaceId: workspaceId });
  const normalizedFormat = String(format || '').toUpperCase();
  if (!['PNG', 'JPEG'].includes(normalizedFormat)) {
    throw new AppError('format must be PNG or JPEG', 400);
  }
  const ids = checkedSlideIds(deck, { slideIds });
  if (!ids) throw new AppError('Choose at least one slide', 400);

  const exportAc = presentationCredit.getFlatAc(PPT_FEATURE.EXPORT);
  await presentationCredit.assertAfford(workspaceId, userId, exportAc);
  const chargeResult = await presentationCredit.chargeFlat({
    workspaceId,
    userId,
    feature: PPT_FEATURE.EXPORT,
    idempotencyKey: `ppt:export:browser:${deck.id}:${downloadId}`,
    metadata: { deckId: deck.id, format: normalizedFormat, slideCount: ids.length, source: 'browser' },
  });
  const creditsCharged = chargeResult.skipped
    ? 0
    : chargeResult.charged || chargeResult.pricing?.athenaCredits || 0;
  if (!chargeResult.skipped && creditsCharged > 0) {
    await presentationDao.incrementDeckCreditsCharged(deck.id, creditsCharged);
  }
  logger.info('presentation_export_browser', {
    deckId: deck.id,
    format: normalizedFormat,
    slideCount: ids.length,
    creditsCharged,
  });
  return { format: normalizedFormat, slideCount: ids.length, creditsCharged };
}

async function getExport({ workspaceId, presentationId, exportId }) {
  const { deck, project } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  let row = await presentationDao.findExport(exportId);
  if (!row || row.deckId !== deck.id) {
    throw new AppError(messages.PRESENTATION_EXPORT_NOT_FOUND, 404);
  }

  if (exportJobIsStale(row)) {
    const staleError =
      row.status === 'QUEUED'
        ? 'Export did not start in time. Please try again.'
        : 'Export timed out on the server. For large decks use PowerPoint (PPTX) or try again.';
    await presentationDao.updateExport(exportId, {
      status: 'FAILED',
      error: staleError,
    });
    row = { ...row, status: 'FAILED', error: staleError };
  }

  const payload = {
    exportId: row.id,
    format: row.format,
    status: row.status,
    error: row.error || null,
    creditsCharged: row.creditsCharged ?? null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };

  if (row.status === 'READY' && row.s3Key) {
    // A multi-slide PNG / JPEG export is a .zip: name it from the stored file, not the format.
    const filename = safeExportFilename(project?.name, exportFileExt(row));
    const presignedUrl = await s3Service.getPresignedGetUrl(row.s3Key, PRESIGN_EXPIRES_SEC, {
      responseContentDisposition: `attachment; filename="${filename}"`,
    });
    payload.presignedUrl = presignedUrl;
    payload.filename = filename;
    payload.url = presignedUrl;
    payload.downloadUrl = presignedUrl;
    payload.expiresIn = PRESIGN_EXPIRES_SEC;
    payload.s3Key = row.s3Key;
  }

  return payload;
}

module.exports = {
  queueExport,
  chargeBrowserExport,
  processExport,
  getExport,
  renderSlideScreenshots,
  buildPptxBuffer,
  buildPdfBuffer,
  buildRasterExport,
  selectExportSlides,
  imageExportOptions,
  exportJobIsStale,
  exportQueueStats,
  svgRasterSize,
  resolveColor,
  resolveExportFontFace,
  editorThemeFonts,
  PRESIGN_EXPIRES_SEC,
};
