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
const { enrichDeckMediaKeysForExport } = require('./presignSlideMedia');
const { normalizeChartContent } = require('./chartContentNormalize');
const { parseCssColor, compositeRgbaOnHex } = require('./theme.service');

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

function exportJobIsStale(row) {
  if (!row || (row.status !== 'QUEUED' && row.status !== 'RENDERING')) return false;
  const now = Date.now();
  const createdAt = row.createdAt ? new Date(row.createdAt).getTime() : now;
  const updatedAt = row.updatedAt ? new Date(row.updatedAt).getTime() : createdAt;

  if (row.status === 'QUEUED') {
    return now - createdAt > EXPORT_MAX_QUEUED_MS;
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

function normalizeExportError(err) {
  const msg = String(err?.message || err || '');
  if (/timeout.*\d{4,6}.*exceeded|Navigation timeout|Waiting failed.*timeout/i.test(msg)) {
    const sec = msg.match(/(\d{4,6})\s*ms/)?.[1];
    const hint = sec ? ` (${Math.round(Number(sec) / 1000)}s limit)` : '';
    return `Export rendering timed out${hint}. For large decks use PowerPoint (PPTX), or try again with fewer slides.`;
  }
  return msg.slice(0, 2000);
}

function safeExportFilename(name, ext) {
  const base = String(name || 'presentation')
    .replace(/[^\w\s.-]/g, '')
    .trim()
    .slice(0, 80) || 'presentation';
  return `${base}.${ext}`;
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

/** Match editor flex verticalAlign → pptxgenjs valign. */
function pptxValign(content = {}) {
  const v = String(content.verticalAlign || content.valign || '').toLowerCase();
  if (v === 'center' || v === 'middle') return 'middle';
  if (v === 'bottom' || v === 'flex-end' || v === 'end') return 'bottom';
  return 'top';
}

/**
 * Typography px (fontSize, spacing, corner radius) → PowerPoint points. These values are authored
 * for the ~900px editor stage (FONT_REF_WIDTH), not the 1920 placement canvas.
 */
function stagePxToPt(px, slideSize = DEFAULT_SLIDE_SIZE_IN) {
  return Math.max(1, Math.round(((Number(px) || 0) * slideSize.w * 72 / FONT_REF_WIDTH) * 10) / 10);
}

/**
 * pptxgenjs only accepts 6-digit hex and silently swaps anything else for black, so
 * rgb()/rgba() (palette cardBg / divider, translucent fills) are flattened onto the slide bg.
 */
function toPptxHex(value, palette, fallback) {
  const raw = String(value || '').trim();
  if (!/^rgba?\(/i.test(raw)) return raw.replace(/^#/, '');
  const rgba = parseCssColor(raw);
  if (!rgba) return String(fallback).replace(/^#/, '');
  return compositeRgbaOnHex(rgba, palette?.bg || '#FFFFFF').replace(/^#/, '').toUpperCase();
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
  const raw = String(resolvePaletteColor(value, palette, fallback) || '').trim();
  const rgba = /^rgba?\(/i.test(raw) ? parseCssColor(raw) : null;
  if (!rgba) return { color: toPptxHex(raw, palette, fallback), alpha: 1 };
  const alpha = rgba.a == null ? 1 : Math.max(0, Math.min(1, Number(rgba.a)));
  const color = compositeRgbaOnHex({ ...rgba, a: 1 }, '#FFFFFF').replace(/^#/, '').toUpperCase();
  return { color, alpha };
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

function resolveFillForExport(fill, palette, fallback = '0A84FF') {
  if (!fill) return { kind: 'solid', color: resolveColor(null, palette, fallback) };
  if (typeof fill === 'string') {
    return { kind: 'solid', color: resolveColor(fill, palette, fallback) };
  }
  if (fill.type === 'gradient' || fill.kind === 'radial' || Array.isArray(fill.stops)) {
    const stops = Array.isArray(fill.stops) ? fill.stops : [];
    const colors = (stops.length
      ? stops
      : [{ color: fill.from || fill.start }, { color: fill.to || fill.end }]
    ).map((s) => resolveColor(s?.color || s?.colorRole || s, palette, fallback));
    return {
      kind: 'gradient',
      colors,
      direction: fill.direction || '135deg',
      angle: fill.angle != null ? Number(fill.angle) : 135,
      radial: fill.kind === 'radial' || fill.gradientKind === 'radial',
    };
  }
  return {
    kind: 'solid',
    color: resolveColor(fill.color || fill.colorRole, palette, fallback),
  };
}

function chartColorHexes(colors, palette, fallback = '0A84FF') {
  if (!Array.isArray(colors) || !colors.length) return [];
  return colors.map((c) => firstHexFromFill(c, palette, fallback));
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

/** pptxgenjs v4: addChart(typeEnum, data[], opts) — not the v3 categories/series object shape. */
function resolvePptxChartTypeEnum(pptx, chartType) {
  const { mapChartType } = require('./elementContent.normalize');
  const t = mapChartType(chartType);
  const ChartType = pptx.ChartType || pptx.charts || {};
  if (t === 'doughnut' || t === 'donut') return ChartType.doughnut || ChartType.donut || 'doughnut';
  if (t === 'pie') return ChartType.pie || 'pie';
  if (t === 'line') return ChartType.line || 'line';
  if (t === 'area') return ChartType.area || 'area';
  return ChartType.bar || 'bar';
}

function resolveExportFontFace(content, el, themeFonts = {}) {
  if (content.fontFamily) return content.fontFamily;
  const role = String(el.role || content.role || '').toLowerCase();
  if (role === 'title' || role === 'heading' || role === 'headline' || role === 'stat_value') {
    return themeFonts.heading || themeFonts.body || null;
  }
  if (role === 'subtitle' || role === 'subheading') {
    return themeFonts.subheading || themeFonts.heading || themeFonts.body || null;
  }
  return themeFonts.body || themeFonts.subheading || themeFonts.heading || null;
}

async function addElementsToPptxSlide(
  s,
  slide,
  palette,
  textColor,
  brandChartColors = [],
  themeFonts = {},
  slideSize = DEFAULT_SLIDE_SIZE_IN,
  pptx = null
) {
  const doc = slide.elements;
  const canvasW = doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = doc.canvas?.height || CANVAS_HEIGHT;
  const toPt = (px) => stagePxToPt(px, slideSize);
  // borderRadius is editor-stage px (like fontSize), not placement-canvas px.
  const inPerPx = slideSize.w / FONT_REF_WIDTH;
  const elements = [...(doc.elements || [])].sort(
    (a, b) => (Number(a.layer) || 0) - (Number(b.layer) || 0)
  );

  for (const el of elements) {
    const box = placementToIn(el.placement, canvasW, canvasH, slideSize);
    const content = el.content || {};
    const rotate = Number(el.placement?.rotation) || 0;
    if (el.type === 'group') continue;

    if (el.type === 'text' || el.type === 'textbox') {
      const textInk = resolveColorAlpha(content.color || content.colorRole, palette, textColor);
      const textColorResolved = textInk.color;
      const fontSizePt = toPt(Number(content.fontSize) || 18);
      const textOpts = {
        x: box.x,
        y: box.y,
        w: box.w,
        h: box.h,
        fontSize: fontSizePt,
        bold: content.bold === true || Number(content.fontWeight) >= 600,
        italic: content.italic === true,
        color: content.fill
          ? firstHexFromFill(content.fill, palette, textColorResolved)
          : textColorResolved,
        align: content.align || 'left',
        valign: pptxValign(content),
        rotate,
      };
      if (!content.fill && pptxTransparency(textInk.alpha) != null) {
        textOpts.transparency = pptxTransparency(textInk.alpha);
      }
      if (content.wrap === 'nowrap') {
        textOpts.shrinkText = true;
        textOpts.wrap = false;
      }
      if (content.letterSpacing != null) {
        // pptxgenjs charSpacing / lineSpacing are in points: em × font size (pt)
        textOpts.charSpacing = Math.round(Number(content.letterSpacing) * fontSizePt * 10) / 10;
      }
      if (content.lineHeight != null) {
        textOpts.lineSpacing = Math.round(Number(content.lineHeight) * fontSizePt);
      }
      const fontFace = resolveExportFontFace(content, el, themeFonts);
      if (Array.isArray(content.runs) && content.runs.length) {
        const runPayload = content.runs.map((run) => ({
          text: String(run.text || ''),
          options: {
            fontSize: fontSizePt,
            bold: run.bold === true || Number(run.fontWeight) >= 600,
            italic: run.italic === true,
            color: firstHexFromFill(
              run.fill || run.color || run.colorRole,
              palette,
              textColorResolved
            ),
            fontFace: run.fontFamily || fontFace || undefined,
          },
        }));
        s.addText(runPayload, {
          x: box.x,
          y: box.y,
          w: box.w,
          h: box.h,
          align: content.align || 'left',
          valign: pptxValign(content),
          rotate,
        });
      } else {
        if (fontFace) textOpts.fontFace = fontFace;
        s.addText(String(content.text || ''), textOpts);
      }
    } else if (el.type === 'image' || el.type === 'icon' || el.type === 'graphic') {
      const url = content.url || content.src;
      const key = content.s3Key || slide.imageRef?.s3Key || null;
      // Inline SVG (compiled diagrams/graphics) takes precedence, matching the editor renderer.
      const inlineSvgPng =
        typeof content.svg === 'string' && content.svg.includes('<svg')
          ? await svgMarkupToPngBuffer(content.svg, {
              width: (Number(el.placement?.width) || 100) * 2,
              height: (Number(el.placement?.height) || 100) * 2,
              color: graphicTintColor(content, palette),
            })
          : null;
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
        if (fit === 'cover' && image.width && image.height) {
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
        s.addImage(imageOpts);
      } else {
        s.addShape('rect', {
          x: box.x,
          y: box.y,
          w: box.w,
          h: box.h,
          fill: { color: 'DDDDDD' },
          line: { color: 'AAAAAA', width: 1 },
        });
        s.addText(el.type === 'icon' ? content.icon || 'icon' : el.type === 'graphic' ? 'graphic' : 'image', {
          x: box.x,
          y: box.y,
          w: box.w,
          h: box.h,
          fontSize: 12,
          color: '666666',
          align: 'center',
          valign: 'middle',
        });
      }
    } else if (el.type === 'shape') {
      const shape = shapeTypeForPptx(content.shape);
      const fillResolved = resolveFillForExport(content.fill, palette, '0A84FF');
      const strokeColor = content.stroke || content.line;
      const strokeWidth = content.strokeWidth != null ? Number(content.strokeWidth) : strokeColor ? 1.5 : 0;
      const shapeOpts = {
        x: box.x,
        y: box.y,
        w: box.w,
        h: box.h,
        line: strokeColor
          ? (() => {
              const ink = resolveColorAlpha(strokeColor, palette, 'E5E5E5');
              return withTransparency({ color: ink.color, width: strokeWidth || 1.5 }, ink.alpha);
            })()
          : { type: 'none' },
        rotate,
      };
      if (content.borderRadius != null || content.shape === 'rounded-rect' || content.shape === 'pill') {
        // pptxgenjs rectRadius is in inches, capped at half the shorter side.
        const maxRadius = Math.min(box.w, box.h) / 2;
        const r = Number(content.borderRadius);
        shapeOpts.rectRadius =
          content.shape === 'pill' ? maxRadius : Math.min(maxRadius, (Number.isFinite(r) ? r : 16) * inPerPx);
      }
      if (fillResolved.kind === 'gradient' && fillResolved.colors.length >= 2) {
        shapeOpts.fill = {
          type: 'gradient',
          color: fillResolved.colors[0],
          color2: fillResolved.colors[fillResolved.colors.length - 1],
          gradientType: fillResolved.radial ? 'radial' : 'linear',
          angle: Number.isFinite(fillResolved.angle) ? fillResolved.angle : 135,
        };
      } else {
        // Editor paints rgba fills and multiplies content.opacity on top — mirror both.
        const fill = content.fill;
        const fillSource = fill && typeof fill === 'object' ? fill.color || fill.colorRole : fill;
        const ink = resolveColorAlpha(fillSource, palette, '0A84FF');
        const shapeOpacity = Number.isFinite(Number(content.opacity)) ? Number(content.opacity) : 1;
        shapeOpts.fill = withTransparency({ color: ink.color }, ink.alpha * shapeOpacity);
      }
      try {
        s.addShape(shape, shapeOpts);
      } catch {
        s.addShape('rect', { ...shapeOpts, shape: undefined });
      }
    } else if (el.type === 'chart') {
      const normalized = normalizeChartContent(content, palette);
      let labels = Array.isArray(normalized.labels) ? normalized.labels : [];
      let series = Array.isArray(normalized.series) ? normalized.series : [];
      const values = Array.isArray(series[0]?.values) ? series[0].values : [];
      if (!labels.length && values.length) {
        labels = values.map((_, i) => `Item ${i + 1}`);
      }
      if (labels.length && values.length && !series.length) {
        series = [{ name: 'Series', values }];
      }
      if (labels.length && series.length && values.length && pptx) {
        try {
          const chartData = series.map((ser) => ({
            name: ser.name || 'Series',
            labels,
            values: (ser.values || []).map((v) => Number(v) || 0),
          }));
          const chartOpts = {
            x: box.x,
            y: box.y,
            w: box.w,
            h: box.h,
            showTitle: false,
            showLegend: false,
          };
          const chartColorSource =
            (Array.isArray(normalized.colors) && normalized.colors.length ? normalized.colors : null) ||
            (Array.isArray(content.colors) && content.colors.length ? content.colors : null) ||
            (Array.isArray(brandChartColors) && brandChartColors.length ? brandChartColors : null);
          if (chartColorSource?.length) {
            chartOpts.chartColors = chartColorHexes(chartColorSource, palette, '0A84FF');
          }
          s.addChart(
            resolvePptxChartTypeEnum(pptx, normalized.chartType || content.chartType || content.chartTypeRaw),
            chartData,
            chartOpts
          );
        } catch (chartErr) {
          logger.warn?.('pptx_chart_export_failed', {
            slideId: slide.id,
            error: chartErr?.message || chartErr,
          });
          s.addText('Chart', {
            x: box.x,
            y: box.y,
            w: box.w,
            h: box.h,
            fontSize: 14,
            color: textColor,
            align: 'center',
            valign: 'middle',
          });
        }
      } else {
        s.addShape('rect', {
          x: box.x,
          y: box.y,
          w: box.w,
          h: box.h,
          fill: { color: 'F5F5F5' },
          line: { color: 'CCCCCC', width: 1 },
        });
        s.addText('Chart', {
          x: box.x,
          y: box.y,
          w: box.w,
          h: box.h,
          fontSize: 14,
          color: '666666',
          align: 'center',
          valign: 'middle',
        });
      }
    } else if (el.type === 'table') {
      const rows = Array.isArray(content.rows)
        ? content.rows
        : Array.isArray(content.cells)
          ? content.cells
          : [];
      if (rows.length) {
        s.addTable(
          rows.map((row, rowIdx) =>
            (Array.isArray(row) ? row : [row]).map((cell) => ({
              text: String(cell ?? ''),
              options: {
                color: textColor,
                fontSize: 12,
                bold: content.hasHeader && rowIdx === 0,
              },
            }))
          ),
          { x: box.x, y: box.y, w: box.w, h: box.h, border: [{ pt: 0.5, color: 'CCCCCC' }] }
        );
      } else {
        s.addText('Table', {
          x: box.x,
          y: box.y,
          w: box.w,
          h: box.h,
          fontSize: 14,
          color: '666666',
          align: 'center',
          valign: 'middle',
        });
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

  const notes = slide.content?.notes;
  if (notes) s.addNotes(String(notes));
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

async function buildPptxBuffer(deck, { slideId, onSlideProcessed } = {}) {
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
  const themeFonts = deck.themeTokens?.fonts || {};
  let slides = [...(deck.slides || [])].sort((a, b) => a.order - b.order);
  if (slideId) slides = slides.filter((s) => s.id === slideId);
  const bgColor = String(palette.bg || 'FFFFFF').replace(/^#/, '');
  const textColor = String(palette.text || '111111').replace(/^#/, '');

  for (const slide of slides) {
    const slideBg =
      slide.content?.background?.color ||
      slide.elements?.backgroundColor ||
      slide.backgroundColor ||
      palette.bg ||
      'FFFFFF';
    const s = pptx.addSlide({
      background: { color: String(slideBg).replace(/^#/, '') },
    });
    const bgFill = slide.elements?.backgroundFill || slide.backgroundFill;
    const bgStart = slide.elements?.backgroundGradientStart || slide.backgroundGradientStart;
    const bgEnd = slide.elements?.backgroundGradientEnd || slide.backgroundGradientEnd;
    if ((bgFill && bgFill.type === 'gradient') || (bgStart && bgEnd)) {
      const fillResolved = resolveFillForExport(
        bgFill && bgFill.type === 'gradient'
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
        palette,
        slideBg
      );
      if (fillResolved.kind === 'gradient' && fillResolved.colors.length >= 2) {
        s.addShape('rect', {
          x: 0,
          y: 0,
          w: '100%',
          h: '100%',
          line: { type: 'none' },
          fill: {
            type: 'gradient',
            color: fillResolved.colors[0],
            color2: fillResolved.colors[fillResolved.colors.length - 1],
            gradientType: fillResolved.radial ? 'radial' : 'linear',
            angle: Number.isFinite(fillResolved.angle) ? fillResolved.angle : 135,
          },
        });
      }
    }
    if (slideHasElements(slide)) {
      await addElementsToPptxSlide(s, slide, palette, textColor, brandChartColors, themeFonts, {
        w: aspect.pptxWidthIn || PPTX_WIDTH_IN,
        h: aspect.pptxHeightIn || PPTX_HEIGHT_IN,
      }, pptx);
    } else {
      await addLegacyToPptxSlide(s, slide, textColor);
    }
    if (typeof onSlideProcessed === 'function') {
      // eslint-disable-next-line no-await-in-loop
      await onSlideProcessed(slide);
    }
  }

  const out = await pptx.write({ outputType: 'nodebuffer' });
  return Buffer.isBuffer(out) ? out : Buffer.from(out);
}

async function withBrowserPage(fn, { args = [] } = {}) {
  let browser;
  try {
    const puppeteer = require('puppeteer');
    const { resolveChromeExecutable } = require('../../shared/utils/chromeExecutable');
    const executablePath = resolveChromeExecutable();
    const launchOpts = {
      headless: true,
      // Desktop Chrome on Windows shows a window on launch even when headless; keep the
      // process hidden and parked offscreen so an export never flashes on the host.
      windowsHide: true,
      pipe: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--font-render-hinting=none',
        '--window-position=-32000,-32000',
        '--mute-audio',
        '--no-first-run',
        '--no-default-browser-check',
        ...args,
      ],
    };
    if (executablePath) {
      launchOpts.executablePath = executablePath;
    } else {
      // Last resort: ask Puppeteer to use the installed Chrome channel.
      launchOpts.channel = 'chrome';
    }

    browser = await puppeteer.launch(launchOpts);
    const page = await browser.newPage();
    return await fn(page);
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch {
        // ignore
      }
    }
  }
}

async function buildPdfBuffer(deck, opts = {}) {
  const aspect = resolveAspectCanvas(deck.aspectRatio);
  const contentTimeout = PUPPETEER_EXPORT_TIMEOUT_MS;
  return withBrowserPage(async (page) => {
    await page.setViewport({ width: aspect.width, height: aspect.height });
    page.setDefaultNavigationTimeout(contentTimeout);
    page.setDefaultTimeout(contentTimeout);
    await page.setContent(await buildDeckHtml(deck, opts), {
      waitUntil: 'networkidle0',
      timeout: contentTimeout,
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

/**
 * Minimal ZIP (store only) for multi-slide raster exports.
 */
function buildZipBuffer(files) {
  const parts = [];
  const central = [];
  let offset = 0;

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
    const local = Buffer.concat([
      u32(0x04034b50),
      u16(20),
      u16(0),
      u16(0),
      u16(0),
      u16(0),
      u32(0),
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
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
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

async function buildRasterExport(deck, { format, slideId, onSlideProcessed } = {}) {
  const type = String(format || 'PNG').toUpperCase() === 'JPEG' ? 'jpeg' : 'png';
  let slides = [...(deck.slides || [])].sort((a, b) => a.order - b.order);
  if (slideId) slides = slides.filter((s) => s.id === slideId);
  if (!slides.length) throw new AppError('No slides to export', 400);

  const images = await renderSlideScreenshots(deck, { slides, format: type, onSlideProcessed });

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
async function renderSlideScreenshots(deck, { slides, format = 'jpeg', onSlide, onSlideProcessed } = {}) {
  const type = String(format || 'jpeg').toLowerCase() === 'png' ? 'png' : 'jpeg';
  const list = Array.isArray(slides) && slides.length
    ? slides
    : [...(deck.slides || [])].sort((a, b) => a.order - b.order);
  if (!list.length) return [];

  const contentTimeout = PUPPETEER_EXPORT_TIMEOUT_MS;
  const jpegQuality = 82;

  return withBrowserPage(async (page) => {
    // Don't let a single broken remote image hang forever.
    page.setDefaultNavigationTimeout(contentTimeout);
    page.setDefaultTimeout(contentTimeout);

    const images = [];
    for (let i = 0; i < list.length; i += 1) {
      const slide = list[i];
      const canvasW = Math.max(320, Math.round(slide.elements?.canvas?.width || CANVAS_WIDTH));
      const canvasH = Math.max(180, Math.round(slide.elements?.canvas?.height || CANVAS_HEIGHT));
      try {
        // eslint-disable-next-line no-await-in-loop
        await page.setViewport({ width: canvasW, height: canvasH, deviceScaleFactor: 1 });
        // eslint-disable-next-line no-await-in-loop
        await page.setContent(await buildDeckHtml({ ...deck, slides: [slide] }), {
          waitUntil: 'networkidle0',
          timeout: contentTimeout,
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
          name: `slide-${String(i + 1).padStart(2, '0')}.${type === 'jpeg' ? 'jpg' : 'png'}`,
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
        logger.warn?.('slide_screenshot_failed', {
          slideId: slide.id,
          error: err.message,
        }) || console.warn('slide screenshot failed', slide.id, err.message);
        if (typeof onSlide === 'function') {
          // eslint-disable-next-line no-await-in-loop
          await onSlide(null, slide, err);
        }
      }
    }
    return images;
  });
}

async function processExport({
  exportId,
  workspaceId,
  userId,
  projectId,
  projectName,
  slideId,
}) {
  const row = await presentationDao.findExport(exportId);
  if (!row) return;

  try {
    await presentationDao.updateExport(exportId, { status: 'RENDERING' });
    const deckRaw = await presentationDao.findDeckById(row.deckId);
    if (!deckRaw) {
      throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
    }
    const deck = enrichDeckMediaKeysForExport(deckRaw);
    const heartbeat = () => touchExportHeartbeat(exportId);

    const format = String(row.format || '').toUpperCase();
    let buffer;
    let contentType;
    let ext;

    if (format === 'PPTX') {
      buffer = await buildPptxBuffer(deck, { slideId, onSlideProcessed: heartbeat });
      contentType = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
      ext = 'pptx';
    } else if (format === 'PDF') {
      await heartbeat();
      buffer = await buildPdfBuffer(deck, { slideId });
      contentType = 'application/pdf';
      ext = 'pdf';
    } else if (format === 'PNG' || format === 'JPEG') {
      const raster = await buildRasterExport(deck, {
        format,
        slideId,
        onSlideProcessed: heartbeat,
      });
      buffer = raster.buffer;
      contentType = raster.contentType;
      ext = raster.ext;
    } else {
      throw new AppError(`Unsupported export format: ${format}`, 400);
    }

    const s3Key = `presentations/${workspaceId}/${deck.id}/exports/${exportId}.${ext}`;
    await s3Service.uploadFileToKey(buffer, s3Key, contentType);

    const chargeResult = await presentationCredit.chargeFlat({
      workspaceId,
      userId,
      feature: PPT_FEATURE.EXPORT,
      idempotencyKey: `ppt:export:${exportId}`,
      metadata: { deckId: deck.id, exportId, format, slideId: slideId || null },
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
    logger.error?.('processExport failed', err) || console.error('processExport failed', err);
    await presentationDao.updateExport(exportId, {
      status: 'FAILED',
      error: normalizeExportError(err),
    });
    await notifyExportFinished({
      userId,
      workspaceId,
      projectId,
      deckId: row.deckId,
      exportId,
      format: row.format,
      status: 'FAILED',
      projectName,
      error: err.message,
    });
  }
}

async function queueExport({ workspaceId, presentationId, userId, format, slideId }) {
  const { deck, project } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });

  const normalizedFormat = String(format || '').toUpperCase();
  if (!['PPTX', 'PDF', 'PNG', 'JPEG'].includes(normalizedFormat)) {
    throw new AppError('format must be PPTX, PDF, PNG, or JPEG', 400);
  }

  if (slideId) {
    const found = (deck.slides || []).some((s) => s.id === slideId);
    if (!found) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);
  }

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
      slideId: slideId || null,
    });
  });

  return {
    exportId: exportRow.id,
    format: normalizedFormat,
    status: 'QUEUED',
    estimatedCredits: exportAc,
    slideId: slideId || null,
  };
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
    const ext =
      String(row.format || 'PPTX').toLowerCase() === 'jpeg'
        ? 'jpg'
        : String(row.format || 'pptx').toLowerCase();
    const filename = safeExportFilename(project?.name, ext);
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
  processExport,
  getExport,
  renderSlideScreenshots,
  buildPptxBuffer,
  resolveColor,
  PRESIGN_EXPIRES_SEC,
};
