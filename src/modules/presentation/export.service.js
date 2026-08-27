const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const logger = require('../../shared/utils/logger');
const presentationDao = require('./presentation.dao');
const presentationCredit = require('./presentationCredit.service');
const { loadPresentationDeck } = require('./deckGeneration.service');
const s3Service = require('../s3/s3.service');
const inboxService = require('../inbox/inbox.service');
const { PPT_FEATURE } = require('../../shared/config/presentationCreditPricing');
const { downloadRemote } = require('../../shared/utils/downloadRemote');
const {
  CANVAS_WIDTH,
  CANVAS_HEIGHT,
  PPTX_WIDTH_IN,
  PPTX_HEIGHT_IN,
  resolveAspectCanvas,
} = require('./presentation.constants');
const { attachPresignedMediaToSlides } = require('./presignSlideMedia');
const {
  cssFromFill,
  firstHexFromFill,
  slideBackgroundCss,
  textPaintCss,
} = require('./canvasFill');

const PRESIGN_EXPIRES_SEC = 3600;

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

function pxToIn(x, y, w, h, canvasW = CANVAS_WIDTH, canvasH = CANVAS_HEIGHT) {
  return {
    x: (Number(x) || 0) / canvasW * PPTX_WIDTH_IN,
    y: (Number(y) || 0) / canvasH * PPTX_HEIGHT_IN,
    w: Math.max(0.1, (Number(w) || 100) / canvasW * PPTX_WIDTH_IN),
    h: Math.max(0.1, (Number(h) || 100) / canvasH * PPTX_HEIGHT_IN),
  };
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

function resolveColor(value, palette, fallback = '111111') {
  if (!value) return String(fallback).replace(/^#/, '');
  if (typeof value === 'object') return firstHexFromFill(value, palette, fallback);
  const key = String(value);
  if (key === 'primary') return String(palette.primary || palette.text || fallback).replace(/^#/, '');
  if (key === 'secondary') return String(palette.secondary || palette.primary || fallback).replace(/^#/, '');
  if (key === 'accent') return String(palette.accent || palette.primary || fallback).replace(/^#/, '');
  if (key === 'text') return String(palette.text || fallback).replace(/^#/, '');
  if (key === 'muted') return String(palette.muted || palette.text || fallback).replace(/^#/, '');
  if (key === 'bg') return String(palette.bg || 'FFFFFF').replace(/^#/, '');
  if (key === 'surface') return String(palette.surface || palette.bg || 'FFFFFF').replace(/^#/, '');
  if (key === 'divider') return String(palette.divider || palette.muted || 'CCCCCC').replace(/^#/, '');
  if (key === 'cardBg') return String(palette.cardBg || palette.surface || 'F5F5F5').replace(/^#/, '');
  if (key === 'gradientStart') return String(palette.gradientStart || palette.bg || fallback).replace(/^#/, '');
  if (key === 'gradientEnd') return String(palette.gradientEnd || palette.surface || fallback).replace(/^#/, '');
  // rgba(...) — pptxgenjs wants hex; fall back
  if (key.startsWith('rgba') || key.startsWith('rgb')) {
    return String(fallback).replace(/^#/, '');
  }
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

function slideHasElements(slide) {
  return (
    slide?.elements &&
    typeof slide.elements === 'object' &&
    Array.isArray(slide.elements.elements) &&
    slide.elements.elements.length > 0
  );
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
  // rounded-rect, pill, flow-process, unknown → rect
  return 'rect';
}

function mapChartTypeForPptx(chartType) {
  const { mapChartType } = require('./elementContent.normalize');
  const t = mapChartType(chartType);
  if (t === 'doughnut') return 'doughnut';
  if (t === 'pie') return 'pie';
  if (t === 'line') return 'line';
  if (t === 'area') return 'area';
  return 'bar';
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

async function addElementsToPptxSlide(s, slide, palette, textColor, brandChartColors = [], themeFonts = {}) {
  const doc = slide.elements;
  const canvasW = doc.canvas?.width || CANVAS_WIDTH;
  const canvasH = doc.canvas?.height || CANVAS_HEIGHT;
  const elements = [...(doc.elements || [])].sort(
    (a, b) => (Number(a.layer) || 0) - (Number(b.layer) || 0)
  );

  for (const el of elements) {
    const box = pxToIn(
      el.placement?.x,
      el.placement?.y,
      el.placement?.width,
      el.placement?.height,
      canvasW,
      canvasH
    );
    const content = el.content || {};
    const rotate = Number(el.placement?.rotation) || 0;

    if (el.type === 'text' || el.type === 'textbox') {
      const textColorResolved = resolveColor(
        content.color || content.colorRole,
        palette,
        textColor
      );
      const textOpts = {
        x: box.x,
        y: box.y,
        w: box.w,
        h: box.h,
        fontSize: Number(content.fontSize) || 18,
        bold: content.bold === true || Number(content.fontWeight) >= 600,
        italic: content.italic === true,
        color: content.fill
          ? firstHexFromFill(content.fill, palette, textColorResolved)
          : textColorResolved,
        align: content.align || 'left',
        valign: 'top',
        rotate,
      };
      if (content.letterSpacing != null) {
        // pptxgenjs: charSpacing roughly maps letter-spacing (em * fontSize)
        textOpts.charSpacing = Math.round(Number(content.letterSpacing) * (Number(content.fontSize) || 18));
      }
      if (content.lineHeight != null) {
        textOpts.lineSpacing = Math.round(Number(content.lineHeight) * (Number(content.fontSize) || 18));
      }
      const fontFace = resolveExportFontFace(content, el, themeFonts);
      if (Array.isArray(content.runs) && content.runs.length) {
        const runPayload = content.runs.map((run) => ({
          text: String(run.text || ''),
          options: {
            fontSize: Number(content.fontSize) || 18,
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
          valign: 'top',
          rotate,
        });
      } else {
        if (fontFace) textOpts.fontFace = fontFace;
        s.addText(String(content.text || ''), textOpts);
      }
    } else if (el.type === 'image' || el.type === 'icon' || el.type === 'graphic') {
      const url = content.url || content.src;
      const key = content.s3Key || slide.imageRef?.s3Key || null;
      const b64 = await fetchImageAsBase64(url, key);
      if (b64) {
        const { flipH, flipV } = contentFlipFlags(content);
        s.addImage({
          data: b64,
          x: box.x,
          y: box.y,
          w: box.w,
          h: box.h,
          rotate,
          flipH,
          flipV,
        });
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
          ? { color: resolveColor(strokeColor, palette, 'E5E5E5'), width: strokeWidth || 1.5 }
          : { type: 'none' },
        rotate,
      };
      if (content.borderRadius != null || content.shape === 'rounded-rect' || content.shape === 'pill') {
        const r = Number(content.borderRadius);
        shapeOpts.rectRadius =
          content.shape === 'pill' ? 0.5 : Number.isFinite(r) ? Math.min(0.5, r / Math.min(box.w, box.h) / 72) : 0.1;
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
        shapeOpts.fill = { color: fillResolved.color };
      }
      try {
        s.addShape(shape, shapeOpts);
      } catch {
        s.addShape('rect', { ...shapeOpts, shape: undefined });
      }
    } else if (el.type === 'chart') {
      const labels = Array.isArray(content.labels)
        ? content.labels
        : Array.isArray(content.data?.labels)
          ? content.data.labels
          : [];
      const series = Array.isArray(content.series)
        ? content.series
        : Array.isArray(content.data?.series)
          ? content.data.series
          : [];
      if (labels.length && series.length) {
        try {
          const chartOpts = {
            x: box.x,
            y: box.y,
            w: box.w,
            h: box.h,
            showTitle: false,
            categories: labels,
            series: series.map((ser) => ({
              name: ser.name || 'Series',
              values: ser.values || [],
            })),
          };
          const chartColorSource =
            (Array.isArray(content.colors) && content.colors.length ? content.colors : null) ||
            (Array.isArray(brandChartColors) && brandChartColors.length ? brandChartColors : null);
          if (chartColorSource?.length) {
            chartOpts.chartColors = chartColorHexes(chartColorSource, palette, '0A84FF');
          }
          s.addChart(mapChartTypeForPptx(content.chartType || content.chartTypeRaw), chartOpts);
        } catch {
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
    const b64 = await fetchImageAsBase64(imageUrl, imageKey);
    if (b64) {
      s.addImage({
        data: b64,
        x: 8.4,
        y: 1.6,
        w: 4.4,
        h: 4.4,
      });
    }
  }

  if (content.notes) s.addNotes(String(content.notes));
}

async function buildPptxBuffer(deck, { slideId } = {}) {
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
      await addElementsToPptxSlide(s, slide, palette, textColor, brandChartColors, themeFonts);
    } else {
      await addLegacyToPptxSlide(s, slide, textColor);
    }
  }

  const out = await pptx.write({ outputType: 'nodebuffer' });
  return Buffer.isBuffer(out) ? out : Buffer.from(out);
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

function buildSlideHtmlPage(slide, palette) {
  const text = palette.text || '#111111';
  const bg = slideBackgroundCss(slide, palette);

  if (slideHasElements(slide)) {
    const canvasW = slide.elements.canvas?.width || CANVAS_WIDTH;
    const canvasH = slide.elements.canvas?.height || CANVAS_HEIGHT;
    const els = [...(slide.elements.elements || [])]
      .sort((a, b) => (Number(a.layer) || 0) - (Number(b.layer) || 0))
      .map((el) => {
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

        if (isText) {
          const fallback = c.color || (c.colorRole && palette[c.colorRole]) || text;
          const ls =
            c.letterSpacing != null ? `letter-spacing:${Number(c.letterSpacing)}em;` : '';
          const lh = c.lineHeight != null ? `line-height:${Number(c.lineHeight)};` : 'line-height:1.25;';
          return `<div style="${style};font-size:${Number(c.fontSize) || 18}px;font-weight:${c.bold || Number(c.fontWeight) >= 600 ? '700' : '400'};text-align:${escapeHtml(c.align || 'left')};white-space:pre-wrap;${ls}${lh}">${htmlTextInner(c, palette, fallback)}</div>`;
        }
        if (el.type === 'image' || el.type === 'icon' || el.type === 'graphic') {
          if (c.url) {
            return `<img src="${escapeHtml(c.url)}" alt="" style="${style};object-fit:${escapeHtml(c.fit || 'cover')}" />`;
          }
          return `<div style="${style};background:#ddd;display:flex;align-items:center;justify-content:center;color:#666;font-size:14px">${escapeHtml(el.type)}</div>`;
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
          return `<div style="${style};background:${escapeHtml(bgCss)};border-radius:${radius};${border}"></div>`;
        }
        if (el.type === 'embed') {
          const title = escapeHtml(c.title || c.provider || 'Link');
          const url = escapeHtml(c.url || c.src || '');
          return `<div style="${style};background:#F8FAFC;border:1px solid #CBD5E1;padding:12px;color:${escapeHtml(text)};font-size:14px"><strong>${title}</strong><div>${url}</div></div>`;
        }
        if (el.type === 'chart') {
          return `<div style="${style}">${htmlChartInner(c, palette)}</div>`;
        }
        if (el.type === 'table') {
          return `<div style="${style};background:#f5f5f5;border:1px solid #ccc;display:flex;align-items:center;justify-content:center;color:#666">${escapeHtml(el.type)}</div>`;
        }
        return '';
      })
      .join('\n');

    return `<section class="slide" style="width:${canvasW}px;height:${canvasH}px;position:relative;background:${escapeHtml(bg)};overflow:hidden">${els}</section>`;
  }

  const content = slide.content || {};
  const bullets = bulletsFromContent(content)
    .map((b) => `<li>${escapeHtml(b)}</li>`)
    .join('');
  const image = slide.imageRef?.url
    ? `<img src="${escapeHtml(slide.imageRef.url)}" alt="" />`
    : '';
  return `
    <section class="slide legacy">
      <div class="text">
        <h1>${escapeHtml(content.title || `Slide ${slide.order}`)}</h1>
        ${content.subtitle ? `<h2>${escapeHtml(content.subtitle)}</h2>` : ''}
        ${content.body ? `<p>${escapeHtml(content.body)}</p>` : ''}
        ${bullets ? `<ul>${bullets}</ul>` : ''}
      </div>
      <div class="media">${image}</div>
    </section>`;
}

async function buildDeckHtml(deck, { slideId } = {}) {
  const palette = deck.themeTokens?.palette || {};
  const text = palette.text || '#111111';
  let slides = [...(deck.slides || [])].sort((a, b) => a.order - b.order);
  if (slideId) slides = slides.filter((s) => s.id === slideId);
  slides = await attachPresignedMediaToSlides(slides);

  const pages = slides.map((slide) => buildSlideHtmlPage(slide, palette)).join('\n');

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <style>
    @page { size: 13.333in 7.5in; margin: 0; }
    body { margin: 0; font-family: Arial, Helvetica, sans-serif; color: ${escapeHtml(text)}; }
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
<body>${pages}</body>
</html>`;
}

async function withBrowserPage(fn) {
  let browser;
  try {
    const puppeteer = require('puppeteer');
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });
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
  return withBrowserPage(async (page) => {
    await page.setViewport({ width: 1920, height: 1080 });
    await page.setContent(await buildDeckHtml(deck, opts), {
      waitUntil: 'networkidle0',
      timeout: 60000,
    });
    const pdf = await page.pdf({
      width: '13.333in',
      height: '7.5in',
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

async function buildRasterExport(deck, { format, slideId } = {}) {
  const type = String(format || 'PNG').toUpperCase() === 'JPEG' ? 'jpeg' : 'png';
  let slides = [...(deck.slides || [])].sort((a, b) => a.order - b.order);
  if (slideId) slides = slides.filter((s) => s.id === slideId);
  if (!slides.length) throw new AppError('No slides to export', 400);

  const images = [];
  for (let i = 0; i < slides.length; i += 1) {
    const slide = slides[i];
    // eslint-disable-next-line no-await-in-loop
    const buf = await withBrowserPage(async (page) => {
      const canvasW = slide.elements?.canvas?.width || CANVAS_WIDTH;
      const canvasH = slide.elements?.canvas?.height || CANVAS_HEIGHT;
      await page.setViewport({ width: canvasW, height: canvasH, deviceScaleFactor: 1 });
      await page.setContent(await buildDeckHtml({ ...deck, slides: [slide] }), {
        waitUntil: 'networkidle0',
        timeout: 60000,
      });
      return page.screenshot({
        type,
        quality: type === 'jpeg' ? 90 : undefined,
        fullPage: false,
      });
    });
    images.push({
      name: `slide-${String(i + 1).padStart(2, '0')}.${type === 'jpeg' ? 'jpg' : 'png'}`,
      data: Buffer.from(buf),
    });
  }

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
    const deck = await presentationDao.findDeckById(row.deckId);
    if (!deck) {
      throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
    }

    const format = String(row.format || '').toUpperCase();
    let buffer;
    let contentType;
    let ext;

    if (format === 'PPTX') {
      buffer = await buildPptxBuffer(deck, { slideId });
      contentType = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
      ext = 'pptx';
    } else if (format === 'PDF') {
      buffer = await buildPdfBuffer(deck, { slideId });
      contentType = 'application/pdf';
      ext = 'pdf';
    } else if (format === 'PNG' || format === 'JPEG') {
      const raster = await buildRasterExport(deck, { format, slideId });
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
      error: String(err.message || err).slice(0, 2000),
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
  const { deck } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  const row = await presentationDao.findExport(exportId);
  if (!row || row.deckId !== deck.id) {
    throw new AppError(messages.PRESENTATION_EXPORT_NOT_FOUND, 404);
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
    const presignedUrl = await s3Service.getPresignedGetUrl(row.s3Key, PRESIGN_EXPIRES_SEC);
    payload.presignedUrl = presignedUrl;
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
  PRESIGN_EXPIRES_SEC,
};
