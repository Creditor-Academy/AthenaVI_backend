/* global window, document */
/**
 * Exports drawn by the editor's own renderer.
 *
 * The frontend ships a headless page, export-render.html, that draws slides with the same
 * component the editor and Present use. Puppeteer opens it, hands it the deck (media URLs
 * presigned here) and then prints it (PDF), screenshots it (PNG / JPEG) or reads back what it
 * drew (fitted font sizes and colours, for PPTX).
 *
 * Where the page lives: EXPORT_RENDER_URL, else `${FRONTEND_URL}/export-render.html`.
 * PPT_EXPORT_RENDERER=legacy switches back to the old server-side HTML renderer.
 */

const sharp = require('sharp');
const logger = require('../../shared/utils/logger');
const { withExportPage } = require('../../shared/utils/exportBrowser');
const { fontCssUrlFromThemeTokens } = require('../../shared/fonts/googleFontsCss');
const { attachPresignedMediaToSlides } = require('./presignSlideMedia');
const { resolveAspectCanvas } = require('./presentation.constants');

/** The page's window.__athenaExport.version this backend needs. */
const MIN_RENDERER_VERSION = 1;
/** The first page version that can leave slide backgrounds out (transparent PNG). */
const TRANSPARENT_RENDERER_VERSION = 2;
/** The editor stage width the page lays slides out at (EDITOR_STAGE_WIDTH in the frontend). */
const STAGE_WIDTH = 900;

const PAGE_LOAD_TIMEOUT_MS =
  Number(process.env.PPT_EXPORT_RENDER_LOAD_TIMEOUT_MS) > 0
    ? Number(process.env.PPT_EXPORT_RENDER_LOAD_TIMEOUT_MS)
    : 45_000;

class RendererUnavailableError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'RendererUnavailableError';
    this.code = 'EXPORT_RENDERER_UNAVAILABLE';
    if (cause) this.cause = cause;
  }
}

function exportRenderUrl() {
  if (String(process.env.PPT_EXPORT_RENDERER || '').toLowerCase() === 'legacy') return null;
  const explicit = String(process.env.EXPORT_RENDER_URL || '').trim();
  if (explicit) return explicit;
  const frontend = String(process.env.FRONTEND_URL || '').trim().replace(/\/+$/, '');
  return frontend ? `${frontend}/export-render.html` : null;
}

function isRendererEnabled() {
  return Boolean(exportRenderUrl());
}

/** Time the page gets to draw the deck (fonts, images, fit-to-box). */
function renderTimeoutMs(slideCount) {
  return Math.min(10 * 60 * 1000, Math.max(60_000, (Number(slideCount) || 0) * 6_000));
}

/** Slides to export, in deck order, with their media presigned for the browser. */
async function deckPayload(deck, { slideIds = null } = {}) {
  let slides = [...(deck.slides || [])].sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
  if (Array.isArray(slideIds) && slideIds.length) {
    const wanted = new Set(slideIds);
    slides = slides.filter((s) => wanted.has(s.id));
  }
  slides = await attachPresignedMediaToSlides(slides);
  return {
    id: deck.id,
    aspectRatio: deck.aspectRatio || '16:9',
    themeTokens: deck.themeTokens || null,
    fontCssUrl: fontCssUrlFromThemeTokens(deck.themeTokens) || null,
    slides,
  };
}

const BLOCKED_HOSTS = new Set(['169.254.169.254', 'metadata.google.internal', '[fd00:ec2::254]']);

/**
 * The page may load its own bundle, fonts and pictures (pictures can be on any site: stock
 * photos, pasted links). It never needs API calls, other pages, frames or cloud metadata.
 */
function allowRequest(request, renderOrigin) {
  const url = request.url();
  if (url.startsWith('data:') || url.startsWith('blob:')) return true;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (!/^https?:$/.test(parsed.protocol)) return false;
  if (BLOCKED_HOSTS.has(parsed.hostname)) return false;
  const type = request.resourceType();
  const sameOrigin = parsed.origin === renderOrigin;
  if (type === 'document') {
    // Only the page itself: no other sites, no frames (embeds are drawn as cards).
    const frame = request.frame();
    const isMainFrame = !frame || !frame.parentFrame();
    return sameOrigin && isMainFrame;
  }
  if (type === 'script' || type === 'xhr' || type === 'fetch' || type === 'websocket' || type === 'eventsource') {
    return sameOrigin;
  }
  return ['image', 'font', 'stylesheet', 'media'].includes(type);
}

/**
 * Open the render page and draw the deck on it.
 * @returns {Promise<{ slides: Array<{ id, stageWidth, stageHeight, canvasWidth, canvasHeight }>, failedImages: string[] }>}
 */
async function openRenderedDeck(page, deck, { slideIds = null, deviceScaleFactor = 1, transparent = false } = {}) {
  const url = exportRenderUrl();
  if (!url) throw new RendererUnavailableError('Export renderer is not configured');
  const origin = new URL(url).origin;

  await page.setRequestInterception(true);
  page.on('request', (request) => {
    if (request.isInterceptResolutionHandled?.()) return;
    if (allowRequest(request, origin)) request.continue();
    else request.abort('blockedbyclient');
  });
  await page.setViewport({ width: STAGE_WIDTH, height: 600, deviceScaleFactor });

  try {
    const response = await page.goto(url, { waitUntil: 'load', timeout: PAGE_LOAD_TIMEOUT_MS });
    if (response && !response.ok()) throw new Error(`HTTP ${response.status()}`);
    await page.waitForFunction(() => window.__athenaExport && window.__athenaExport.loaded, {
      timeout: PAGE_LOAD_TIMEOUT_MS,
    });
  } catch (err) {
    throw new RendererUnavailableError(`Export renderer page did not load (${url}): ${err.message}`, err);
  }
  const version = await page.evaluate(() => window.__athenaExport.version);
  if (!(Number(version) >= MIN_RENDERER_VERSION)) {
    throw new RendererUnavailableError(
      `Export renderer version ${version} is older than the required ${MIN_RENDERER_VERSION}`
    );
  }

  const payload = await deckPayload(deck, { slideIds });
  const timeoutMs = renderTimeoutMs(payload.slides.length);
  page.setDefaultTimeout(timeoutMs + 30_000);
  if (transparent && Number(version) < TRANSPARENT_RENDERER_VERSION) {
    logger.warn('export_renderer_no_transparency', { deckId: deck.id, version });
  }
  const result = await page.evaluate(
    (data) => window.__athenaExport.render(data),
    { deck: payload, timeoutMs, transparent: Boolean(transparent) }
  );
  if (result?.failedImages?.length) {
    logger.warn('export_render_images_failed', {
      deckId: deck.id,
      count: result.failedImages.length,
      sample: result.failedImages.slice(0, 5).map((u) => String(u).split('?')[0]),
    });
  }
  return { ...result, rendererVersion: version };
}

/** PDF of the deck: vector text, links kept, one page per slide. */
async function renderDeckPdf(deck, { slideIds = null } = {}) {
  const aspect = resolveAspectCanvas(deck.aspectRatio);
  return withExportPage(async (page) => {
    const { slides } = await openRenderedDeck(page, deck, { slideIds });
    if (!slides.length) throw new Error('No slides to export');
    const stageWidth = slides[0].stageWidth || STAGE_WIDTH;
    const pdf = await page.pdf({
      width: `${aspect.pptxWidthIn}in`,
      height: `${aspect.pptxHeightIn}in`,
      // The page lays slides out 900 CSS px wide: scale them to exactly fill the page width.
      scale: (aspect.pptxWidthIn * 96) / stageWidth,
      printBackground: true,
      margin: { top: 0, right: 0, bottom: 0, left: 0 },
      timeout: renderTimeoutMs(slides.length),
    });
    return Buffer.from(pdf);
  });
}

/**
 * One image per slide, at the deck's canvas size × `scale` (1920×1080 for a 16:9 deck at 1×).
 * @returns {Promise<Array<{ slideId: string, data: Buffer }>>}
 */
async function renderDeckImages(
  deck,
  { slideIds = null, format = 'png', scale = 1, quality = 90, transparent = false, onSlide } = {}
) {
  const type = String(format).toLowerCase() === 'jpeg' || String(format).toLowerCase() === 'jpg' ? 'jpeg' : 'png';
  // Only PNG has transparency: the page leaves slide backgrounds out and Chrome keeps the alpha.
  const clear = type === 'png' && Boolean(transparent);
  const canvasWidth = resolveAspectCanvas(deck.aspectRatio).width;
  const deviceScaleFactor = (canvasWidth / STAGE_WIDTH) * (Number(scale) > 0 ? Number(scale) : 1);
  return withExportPage(async (page) => {
    const { slides } = await openRenderedDeck(page, deck, { slideIds, deviceScaleFactor, transparent: clear });
    const images = [];
    for (const slide of slides) {
      // Exact clip from the slide's own box: a 900px stage of a 1080px slide is 506.25px tall,
      // and element screenshots round that to the wrong pixel height.
      const top = await page.evaluate((id) => {
        const node = [...document.querySelectorAll('.export-slide')].find((n) => n.dataset.slideId === id);
        return node ? node.getBoundingClientRect().top + window.scrollY : null;
      }, slide.id);
      if (top == null) throw new Error(`Slide ${slide.id} was not drawn`);
      const stageHeight = (STAGE_WIDTH * slide.canvasHeight) / slide.canvasWidth;
      let data = Buffer.from(
        await page.screenshot({
          type,
          ...(type === 'jpeg' ? { quality } : {}),
          ...(clear ? { omitBackground: true } : {}),
          clip: { x: 0, y: top, width: STAGE_WIDTH, height: stageHeight },
          captureBeyondViewport: true,
        })
      );
      const width = Math.round(slide.canvasWidth * (Number(scale) > 0 ? Number(scale) : 1));
      const height = Math.round(slide.canvasHeight * (Number(scale) > 0 ? Number(scale) : 1));
      const meta = await sharp(data).metadata();
      if (meta.width !== width || meta.height !== height) {
        const resized = sharp(data).resize(width, height, { fit: 'fill' });
        data = await (type === 'jpeg' ? resized.jpeg({ quality }) : resized.png()).toBuffer();
      }
      images.push({ slideId: slide.id, data });
      if (typeof onSlide === 'function') await onSlide(slide);
    }
    return images;
  });
}

/**
 * What the editor renderer drew for every text element (fitted font size in editor stage px,
 * colour), by slide. Used to build PPTX text that matches the editor.
 */
async function measureDeckText(deck, { slideIds = null } = {}) {
  return withExportPage(async (page) => {
    await openRenderedDeck(page, deck, { slideIds });
    return page.evaluate(() => window.__athenaExport.measure());
  });
}

/**
 * A slide with the elements the editor drew in place of the saved ones (same canvas, background
 * and other slide settings). Unchanged when the render page didn't report them.
 */
function withStageElements(slide, stage) {
  if (!stage || !Array.isArray(stage.elements)) return slide;
  const doc = slide.elements && typeof slide.elements === 'object' ? slide.elements : {};
  // Background elements are drawn as the slide background, not as elements.
  const hadBackgroundElement = (doc.elements || []).some(
    (el) => el?.content?.useAsBackground || (doc.backgroundImageElementId && el?.id === doc.backgroundImageElementId)
  );
  return {
    ...slide,
    elements: {
      ...doc,
      canvas: stage.canvas || doc.canvas,
      elements: stage.elements,
      ...(hadBackgroundElement && !doc.backgroundImage ? { backgroundFromElement: true } : {}),
    },
  };
}

/** Pictures are cut at 1.5× the deck's canvas resolution (2880px wide for 16:9). */
const PICTURE_SCALE = 1.5;

/**
 * Everything PPTX takes from the editor renderer, in one browser session:
 * - textMetrics: fitted font size and colour of every text element;
 * - tableMetrics: tables as drawn (cells, sizes, colours, borders);
 * - pictures: elements PowerPoint can't draw natively (pptxCapability), each a transparent PNG
 *   with its box in canvas px (shadows / glows included);
 * - backgrounds: slide backgrounds that are an image or gradient, as JPEG.
 */
async function capturePptxAssets(deck, { slideIds = null, target = 'powerpoint' } = {}) {
  const { pptxRasterPlan } = require('./pptxCapability');
  const canvasWidth = resolveAspectCanvas(deck.aspectRatio).width;
  const deviceScaleFactor = (canvasWidth / STAGE_WIDTH) * PICTURE_SCALE;
  const wanted = Array.isArray(slideIds) && slideIds.length ? new Set(slideIds) : null;

  return withExportPage(async (page) => {
    const { rendererVersion } = await openRenderedDeck(page, deck, { slideIds, deviceScaleFactor });
    // The elements the editor drew (normalised, layout-finished, without the ones it doesn't
    // paint). PPTX is built from these; older render pages don't report them.
    const stageSlides = await page.evaluate(() =>
      typeof window.__athenaExport.stageSlides === 'function' ? window.__athenaExport.stageSlides() : {}
    );
    const planSlides = (deck.slides || [])
      .filter((s) => !wanted || wanted.has(s.id))
      .map((s) => withStageElements(s, stageSlides[s.id]));
    const plan = pptxRasterPlan(planSlides, { target });
    const textMetrics = await page.evaluate(() => window.__athenaExport.measure());
    // Tables as drawn (older render pages don't measure them: PPTX then uses the CSS defaults).
    const tableMetrics = await page.evaluate(() =>
      typeof window.__athenaExport.measureTables === 'function' ? window.__athenaExport.measureTables() : {}
    );
    const pictures = {};
    const backgrounds = {};
    const capture = async (target, type) => {
      const area = await page.evaluate((t) => window.__athenaExport.isolate(t), target);
      if (!area) return null;
      const data = Buffer.from(
        await page.screenshot({
          type,
          ...(type === 'jpeg' ? { quality: 88 } : { omitBackground: true }),
          clip: area.clip,
          captureBeyondViewport: true,
        })
      );
      return { data, box: area.box };
    };

    try {
      for (const slide of plan) {
        if (slide.background) {
          const shot = await capture({ slideId: slide.slideId }, 'jpeg');
          if (shot) backgrounds[slide.slideId] = `image/jpeg;base64,${shot.data.toString('base64')}`;
        }
        for (const el of slide.elements) {
          const shot = await capture(
            { slideId: slide.slideId, elementId: el.id, margin: el.margin },
            'png'
          );
          if (!shot) continue;
          pictures[slide.slideId] = pictures[slide.slideId] || {};
          pictures[slide.slideId][el.id] = {
            data: `image/png;base64,${shot.data.toString('base64')}`,
            box: shot.box,
            reason: el.reason,
            ...(el.fallbackOnly ? { fallbackOnly: true } : {}),
          };
        }
      }
    } finally {
      await page.evaluate(() => window.__athenaExport.release()).catch(() => {});
    }
    return { textMetrics, tableMetrics, pictures, backgrounds, stageSlides, rendererVersion };
  });
}

module.exports = {
  RendererUnavailableError,
  MIN_RENDERER_VERSION,
  exportRenderUrl,
  isRendererEnabled,
  renderDeckPdf,
  renderDeckImages,
  measureDeckText,
  capturePptxAssets,
  withStageElements,
  allowRequest,
};
