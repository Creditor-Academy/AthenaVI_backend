/**
 * Brand guideline deck templates.
 *
 * Every template produces the same 8 slides (same order + layoutIds) from the same kit
 * content; templates only change the visual frame, surfaces, and cover.
 *
 * Renderer constraints these layouts are written around (AIPptEditor / PDF / PPTX):
 * - placement is canvas px (1920x1080), but fontSize / borderRadius are editor-stage px (~900 wide).
 * - the editor stretches any box below 40x24 canvas px, so no hairline rules.
 * - the editor forces text to be readable against palette.bg (not the shape behind it), so
 *   text never sits on a coloured block; dark templates switch the whole deck palette instead.
 * - letterSpacing / verticalAlign / textTransform aren't honoured by every exporter — avoided.
 * - image elements carry s3Key so the presign step can refresh expired URLs.
 */
const crypto = require('crypto');
const s3Service = require('../s3/s3.service');
const themeService = require('../presentation/theme.service');
const brandKitService = require('./brandKit.service');
const { injectBrandLogo } = require('../presentation/layoutToElements');

const CANVAS = { width: 1920, height: 1080 };
const STAGE_TO_CANVAS = CANVAS.width / 900;
const MARGIN = 120;
const CONTENT_W = CANVAS.width - MARGIN * 2;
const CONTENT_TOP = 280;
const GAP = 40;
const SLIDE_COUNT = 8;

/** Editor-stage font sizes shared by every template. */
const TYPE = {
  kicker: 10,
  title: 30,
  label: 10,
  subhead: 15,
  body: 12,
  caption: 10,
  footer: 9,
};

const GUIDELINE_TEMPLATES = {
  minimal: {
    id: 'minimal',
    name: 'Minimal',
    description: 'Clean white pages, flat sections, and generous whitespace.',
    appearance: 'light',
    panels: false,
    radius: 4,
    marker: 'rect',
  },
  corporate: {
    id: 'corporate',
    name: 'Corporate',
    description: 'Structured layout with a brand side rail, content cards, and a footer band.',
    appearance: 'light',
    panels: true,
    radius: 8,
    marker: null,
  },
  midnight: {
    id: 'midnight',
    name: 'Midnight',
    description: 'Dark, high-contrast deck built on your dark-mode palette.',
    appearance: 'dark',
    panels: true,
    radius: 14,
    marker: 'pill',
  },
};

const DEFAULT_GUIDELINE_TEMPLATE_ID = 'minimal';
const GUIDELINE_TEMPLATE_IDS = Object.keys(GUIDELINE_TEMPLATES);

function getGuidelineTemplate(templateId) {
  return GUIDELINE_TEMPLATES[templateId] || GUIDELINE_TEMPLATES[DEFAULT_GUIDELINE_TEMPLATE_ID];
}

// ── Element primitives ────────────────────────────────────────────────

function newId(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString('hex')}`;
}

function box(x, y, width, height) {
  return {
    x: Math.round(x),
    y: Math.round(y),
    width: Math.round(width),
    height: Math.round(height),
    rotation: 0,
    opacity: 1,
  };
}

function text(id, value, placement, style = {}) {
  return {
    id: newId(id),
    type: 'text',
    layer: style.layer ?? 3,
    placement,
    content: {
      text: String(value ?? ''),
      fontSize: style.fontSize ?? TYPE.body,
      bold: style.bold ?? false,
      fontWeight: style.fontWeight ?? (style.bold ? 700 : 400),
      align: style.align ?? 'left',
      colorRole: style.colorRole ?? 'text',
      lineHeight: style.lineHeight ?? 1.4,
      fontFamily: style.fontFamily ?? null,
    },
    role: style.role ?? 'body',
  };
}

function shape(id, placement, fill, opts = {}) {
  const radius = opts.radius ?? 0;
  const content = {
    shape: opts.shape || (radius > 0 ? 'rounded-rect' : 'rect'),
    fill: fill.color ? { type: 'solid', color: fill.color } : { type: 'solid', colorRole: fill.colorRole },
  };
  if (radius > 0) content.borderRadius = radius;
  if (opts.stroke) {
    content.stroke = opts.stroke;
    content.strokeWidth = opts.strokeWidth ?? 1;
  }
  return { id: newId(id), type: 'shape', layer: opts.layer ?? 1, placement, content, role: opts.role || id };
}

function image(id, media, placement, opts = {}) {
  const content = { url: media.url, fit: opts.fit || 'contain', alt: opts.alt || id };
  if (media.s3Key) content.s3Key = media.s3Key;
  if (opts.radius) content.borderRadius = opts.radius;
  return { id: newId(id), type: 'image', layer: opts.layer ?? 3, placement, content, role: opts.role || 'image' };
}

// ── Text measuring (rough, keeps boxes from clipping) ─────────────────

function fontPx(fontSize) {
  return fontSize * STAGE_TO_CANVAS;
}

/** charWidth is average glyph width in em; bold display text needs more (PPTX may fall back to a wider font). */
function estimateLines(value, fontSize, width, charWidth = 0.52) {
  const charsPerLine = Math.max(8, Math.floor(width / (fontPx(fontSize) * charWidth)));
  return String(value || '')
    .split('\n')
    .reduce((sum, line) => sum + Math.max(1, Math.ceil(line.length / charsPerLine)), 0);
}

function textHeight(value, fontSize, width, lineHeight, charWidth) {
  return Math.ceil(estimateLines(value, fontSize, width, charWidth) * fontPx(fontSize) * lineHeight) + 8;
}

function clip(value, max) {
  const s = String(value || '').trim();
  return s.length > max ? `${s.slice(0, max - 1).trimEnd()}…` : s;
}

function bulletList(items, maxItems, maxChars) {
  return items
    .filter(Boolean)
    .slice(0, maxItems)
    .map((item) => `•  ${clip(item, maxChars)}`)
    .join('\n');
}

// ── Colour helpers ────────────────────────────────────────────────────

const SWATCH_STROKE = { light: '#E2E8F0', dark: '#334155' };

function hexToRgbLabel(hex) {
  const rgb = themeService.parseHexColor(hex);
  return rgb ? `RGB ${rgb.r} ${rgb.g} ${rgb.b}` : '';
}

function isDarkHex(hex) {
  const lum = themeService.relativeLuminance(hex);
  return lum != null && lum < 0.35;
}

const FALLBACK_DARK_PALETTE = {
  bg: '#0B1120',
  text: '#F8FAFC',
  muted: '#94A3B8',
  surface: '#111827',
  divider: 'rgba(255,255,255,0.12)',
  cardBg: 'rgba(255,255,255,0.06)',
  gradientStart: '#0B1120',
  gradientEnd: '#111827',
  shadow: 'rgba(0,0,0,0.4)',
};

function readable(fg, bg) {
  return (themeService.contrastRatio(fg, bg) || 0) >= themeService.AA_CONTRAST_RATIO;
}

/**
 * Kit `muted` often points at a brand shade that only works on one appearance, and the PDF
 * exporter (unlike the editor) never repairs contrast — so guarantee readable text/muted here.
 */
function withReadableInk(palette) {
  const dark = isDarkHex(palette.bg);
  const next = { ...palette };
  if (!readable(next.text, next.bg)) next.text = dark ? '#F8FAFC' : '#0F172A';
  if (!readable(next.muted, next.bg)) next.muted = dark ? '#94A3B8' : '#475569';
  return next;
}

/**
 * Deck-level theme tokens for a template. Dark templates promote the kit's dark palette
 * (or a neutral dark fallback) to `palette` so the editor's readability pass keeps light text.
 */
function deckThemeTokensForTemplate(themeTokens, templateId) {
  const template = getGuidelineTemplate(templateId);
  const light = themeTokens.palette || {};
  const tokens = { ...themeTokens, guidelineTemplateId: template.id };
  if (template.appearance !== 'dark') return { ...tokens, palette: withReadableInk(light) };

  const dark = themeTokens.paletteDark;
  const darkUsable = dark && isDarkHex(dark.bg) && readable(dark.text, dark.bg);
  const palette = darkUsable
    ? { ...dark }
    : { ...light, ...FALLBACK_DARK_PALETTE, primary: light.primary, secondary: light.secondary, accent: light.accent };
  return { ...tokens, palette: withReadableInk(palette), paletteLight: light };
}

/** Brand primary for small labels only when it is readable on the deck background. */
function accentInk(ctx) {
  return readable(ctx.palette.primary, ctx.palette.bg) ? 'primary' : 'text';
}

// ── Shared slide frame ────────────────────────────────────────────────

function frame(ctx, index, kicker, title) {
  const { template, kit } = ctx;
  const els = [shape('bg', box(0, 0, CANVAS.width, CANVAS.height), { colorRole: 'bg' }, { layer: 0, role: 'bg' })];

  let kickerX = MARGIN;
  if (template.id === 'corporate') {
    els.push(shape('rail', box(0, 0, 40, CANVAS.height), { colorRole: 'primary' }, { layer: 1 }));
    els.push(shape('footer_band', box(40, CANVAS.height - 80, CANVAS.width - 40, 80), { colorRole: 'cardBg' }, { layer: 1 }));
  }
  if (template.marker) {
    // 48x24 is the smallest mark the editor renders without stretching (min 40x24).
    els.push(shape('marker', box(MARGIN, 100, 48, 24), { colorRole: 'primary' }, { layer: 2, shape: template.marker }));
    kickerX = MARGIN + 68;
  }

  const num = String(index).padStart(2, '0');
  els.push(
    text('kicker', `${num}   ${kicker.toUpperCase()}`, box(kickerX, 96, 900, 34), {
      fontSize: TYPE.kicker,
      bold: true,
      colorRole: accentInk(ctx),
      role: 'caption',
    })
  );
  els.push(
    text('title', title, box(MARGIN, 140, CONTENT_W, 96), {
      fontSize: TYPE.title,
      bold: true,
      lineHeight: 1.15,
      role: 'title',
    })
  );

  const footerY = template.id === 'corporate' ? CANVAS.height - 56 : CANVAS.height - 72;
  els.push(
    text('footer_brand', `${clip(kit.name, 60)}  ·  Brand Guidelines`, box(MARGIN, footerY, 900, 32), {
      fontSize: TYPE.footer,
      colorRole: 'muted',
      role: 'caption',
    })
  );
  els.push(
    text('footer_page', `${num} / ${String(SLIDE_COUNT).padStart(2, '0')}`, box(CANVAS.width - MARGIN - 300, footerY, 300, 32), {
      fontSize: TYPE.footer,
      colorRole: 'muted',
      align: 'right',
      role: 'caption',
    })
  );
  return els;
}

/** Optional card surface behind a block (panel templates only). */
function panel(ctx, id, x, y, w, h) {
  if (!ctx.template.panels) return [];
  return [shape(id, box(x, y, w, h), { colorRole: 'cardBg' }, { radius: ctx.template.radius, layer: 1 })];
}

function inset(ctx) {
  return ctx.template.panels ? 40 : 0;
}

/** Label + body block; returns elements and the height it used. */
function labelledBlock(ctx, id, { x, y, w, h, label, body, bodySize = TYPE.body, bodyRole = 'body', lineHeight = 1.5 }) {
  const pad = inset(ctx);
  const innerW = w - pad * 2;
  const els = [...panel(ctx, `${id}_panel`, x, y, w, h)];
  els.push(
    text(`${id}_label`, label.toUpperCase(), box(x + pad, y + pad, innerW, 32), {
      fontSize: TYPE.label,
      bold: true,
      colorRole: accentInk(ctx),
      role: 'caption',
    })
  );
  els.push(
    text(`${id}_body`, body, box(x + pad, y + pad + 44, innerW, h - pad * 2 - 44), {
      fontSize: bodySize,
      lineHeight,
      role: bodyRole,
    })
  );
  return els;
}

function slideDoc(elements) {
  return { version: 1, canvas: CANVAS, elements };
}

// ── 1. Cover ──────────────────────────────────────────────────────────

function buildCover(ctx) {
  const { kit, template, tokens } = ctx;
  const tagline = clip(kit.data?.meta?.tagline, 160);
  const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });

  const els = [shape('bg', box(0, 0, CANVAS.width, CANVAS.height), { colorRole: 'bg' }, { layer: 0, role: 'bg' })];
  let textW = 1400;

  if (template.id === 'corporate') {
    textW = 1300 - MARGIN - 80;
    els.push(shape('cover_panel', box(1300, 0, 620, CANVAS.height), { colorRole: 'primary' }, { layer: 1 }));
    els.push(shape('cover_panel_accent', box(1300, 760, 620, 320), { colorRole: 'secondary' }, { layer: 2 }));
  }

  const nameSize = template.id === 'midnight' ? 60 : 54;
  const name = clip(kit.name, 80);
  const nameH = textHeight(name, nameSize, textW, 1.1, 0.64);
  const nameY = Math.max(300, 470 - nameH / 2);

  if (template.id === 'midnight') {
    els.push(shape('cover_bar', box(MARGIN, nameY - 64, 160, 24), { colorRole: 'primary' }, { layer: 2 }));
  } else if (template.id === 'minimal') {
    els.push(shape('cover_marker', box(MARGIN, nameY - 64, 48, 24), { colorRole: 'primary' }, { layer: 2 }));
  }

  els.push(
    text('brand_name', name, box(MARGIN, nameY, textW, nameH), {
      fontSize: nameSize,
      bold: (tokens.fonts?.headingWeight ?? 700) >= 600,
      lineHeight: 1.1,
      role: 'title',
    })
  );
  let y = nameY + nameH + 24;
  els.push(
    text('guideline_title', 'Brand Guidelines', box(MARGIN, y, textW, 64), {
      fontSize: 22,
      colorRole: accentInk(ctx),
      role: 'subtitle',
    })
  );
  y += 88;
  if (tagline) {
    const tagH = textHeight(tagline, 14, Math.min(textW, 1000), 1.45);
    els.push(
      text('tagline', tagline, box(MARGIN, y, Math.min(textW, 1000), tagH), {
        fontSize: 14,
        colorRole: 'muted',
        lineHeight: 1.45,
        role: 'tagline',
      })
    );
  }
  els.push(
    text('date', `Version 1.0  ·  ${dateStr}`, box(MARGIN, CANVAS.height - 120, 800, 32), {
      fontSize: TYPE.caption,
      colorRole: 'muted',
      role: 'caption',
    })
  );

  let doc = slideDoc(els);
  const logo = brandKitService.pickLogoForBackground(tokens);
  if (logo?.url || logo?.s3Key) {
    const url = logo.url || s3Service.buildPublicUrl(logo.s3Key);
    doc = injectBrandLogo(doc, { ...logo, url }, { contentType: 'title', force: true });
  }

  return {
    order: 1,
    contentType: 'title',
    layoutId: 'brand_guideline_cover',
    content: { title: kit.name, subtitle: tagline, background: { color: tokens.palette?.bg } },
    elements: doc,
  };
}

// ── 2. Voice ──────────────────────────────────────────────────────────

function buildVoice(ctx) {
  const data = ctx.kit.data || {};
  const voice = data.voice || {};
  const els = frame(ctx, 2, 'Voice', 'Brand voice & messaging');

  const topH = 240;
  const mission = clip(data.meta?.tagline, 150) || 'Add a tagline or mission statement to the brand kit to feature it here.';
  els.push(
    ...labelledBlock(ctx, 'mission', {
      x: MARGIN,
      y: CONTENT_TOP,
      w: CONTENT_W,
      h: topH,
      label: 'Mission',
      body: mission,
      bodySize: 18,
      bodyRole: 'subheading',
      lineHeight: 1.3,
    })
  );

  const rowY = CONTENT_TOP + topH + GAP;
  const rowH = 920 - rowY;
  const colW = (CONTENT_W - GAP * 2) / 3;
  const toneAudience = [
    `Tone — ${clip(voice.tone, 70) || 'Professional, clear, and confident.'}`,
    `Audience — ${clip(voice.audience, 70) || 'Customers, partners, and decision makers.'}`,
  ].join('\n');
  const dos = Array.isArray(voice.dos) && voice.dos.length
    ? voice.dos
    : ['Lead with the benefit to the reader.', 'Use short sentences and plain words.', 'Stay consistent across every channel.'];
  const donts = Array.isArray(voice.donts) && voice.donts.length
    ? voice.donts
    : ['Use jargon or internal acronyms.', 'Overpromise or exaggerate.', 'Mix tones within one piece.'];
  els.push(
    ...labelledBlock(ctx, 'tone', { x: MARGIN, y: rowY, w: colW, h: rowH, label: 'Tone & audience', body: toneAudience }),
    ...labelledBlock(ctx, 'dos', { x: MARGIN + colW + GAP, y: rowY, w: colW, h: rowH, label: 'Do', body: bulletList(dos, 3, 60) }),
    ...labelledBlock(ctx, 'donts', {
      x: MARGIN + (colW + GAP) * 2,
      y: rowY,
      w: colW,
      h: rowH,
      label: "Don't",
      body: bulletList(donts, 3, 60),
    })
  );

  return {
    order: 2,
    contentType: 'image+text',
    layoutId: 'brand_guideline_mission_voice',
    content: { title: 'Brand voice & messaging' },
    elements: slideDoc(els),
  };
}

// ── 3. Colour ─────────────────────────────────────────────────────────

function roleSwatches(data, entries) {
  const map = brandKitService.colorMap(data);
  const roles = data.colorRoles || {};
  const named = new Map((data.colors || []).map((c) => [c.id, c]));
  const seen = new Set();
  const out = [];
  for (const { key, label } of entries) {
    const id = roles[key];
    if (!id || seen.has(id) || !named.has(id)) continue;
    seen.add(id);
    out.push({ label, name: named.get(id).name || label, hex: brandKitService.resolveHex(map, id, '#000000').toUpperCase() });
  }
  return out;
}

function swatchRow(ctx, id, swatches, y, swatchH) {
  const els = [];
  if (!swatches.length) return els;
  const n = Math.max(swatches.length, 4);
  const w = (CONTENT_W - GAP * (n - 1)) / n;
  const stroke = SWATCH_STROKE[ctx.template.appearance];
  swatches.forEach((s, i) => {
    const x = MARGIN + i * (w + GAP);
    els.push(shape(`${id}_${i}`, box(x, y, w, swatchH), { color: s.hex }, { radius: ctx.template.radius, stroke, layer: 2 }));
    els.push(
      text(`${id}_name_${i}`, clip(s.name, 32), box(x, y + swatchH + 16, w, 36), {
        fontSize: 12,
        bold: true,
        role: 'subheading',
      })
    );
    els.push(
      text(`${id}_spec_${i}`, `${s.label}\n${s.hex}  ·  ${hexToRgbLabel(s.hex)}`, box(x, y + swatchH + 54, w, 64), {
        fontSize: TYPE.caption,
        colorRole: 'muted',
        lineHeight: 1.45,
        role: 'caption',
      })
    );
  });
  return els;
}

function buildColors(ctx) {
  const data = ctx.kit.data || {};
  const els = frame(ctx, 3, 'Color', 'Color palette');

  const light = roleSwatches(data, [
    { key: 'primary', label: 'Primary' },
    { key: 'secondary', label: 'Secondary' },
    { key: 'accent', label: 'Accent' },
    { key: 'bg', label: 'Background' },
    { key: 'text', label: 'Text' },
  ]);
  const dark = roleSwatches(data, [
    { key: 'primaryDark', label: 'Dark primary' },
    { key: 'bgDark', label: 'Dark background' },
    { key: 'textDark', label: 'Dark text' },
  ]);

  els.push(
    text('light_label', 'LIGHT MODE', box(MARGIN, CONTENT_TOP, 600, 32), {
      fontSize: TYPE.label,
      bold: true,
      colorRole: accentInk(ctx),
      role: 'caption',
    }),
    ...swatchRow(ctx, 'swatch_light', light, CONTENT_TOP + 44, 180)
  );

  if (dark.length) {
    const darkY = CONTENT_TOP + 44 + 180 + 140;
    els.push(
      text('dark_label', 'DARK MODE', box(MARGIN, darkY, 600, 32), {
        fontSize: TYPE.label,
        bold: true,
        colorRole: accentInk(ctx),
        role: 'caption',
      }),
      ...swatchRow(ctx, 'swatch_dark', dark, darkY + 44, 110)
    );
  }

  return {
    order: 3,
    contentType: 'section_divider',
    layoutId: 'brand_guideline_colors',
    content: { title: 'Color palette' },
    elements: slideDoc(els),
  };
}

// ── 4. Logo ───────────────────────────────────────────────────────────

const LOGO_VARIANTS = [
  { roles: ['primary', ''], label: 'Primary logo', dark: false },
  { roles: ['with-name-adjacent'], label: 'Horizontal lockup', dark: false },
  { roles: ['with-name-below'], label: 'Stacked lockup', dark: false },
  { roles: ['dark', 'dark-mode'], label: 'On light backgrounds', dark: false },
  { roles: ['light', 'light-mode'], label: 'On dark backgrounds', dark: true },
  { roles: ['with-name-adjacent-dark'], label: 'Horizontal · dark', dark: true },
  { roles: ['with-name-below-dark'], label: 'Stacked · dark', dark: true },
  { roles: ['monochrome', 'black'], label: 'Monochrome', dark: false },
  { roles: ['white'], label: 'Reversed', dark: true },
];

function buildLogos(ctx) {
  const data = ctx.kit.data || {};
  const usage = data.usage || {};
  const logos = (ctx.kit.media || []).filter((m) => m.kind === 'logo' && m.url);
  const els = frame(ctx, 4, 'Logo', 'Logo system');

  const found = [];
  for (const variant of LOGO_VARIANTS) {
    const media = logos.find((m) => variant.roles.includes(m.role || ''));
    if (media) found.push({ ...variant, media });
    if (found.length === 6) break;
  }

  const gridW = 1000;
  const cols = 3;
  const tileW = (gridW - GAP * (cols - 1)) / cols;
  const tileH = 220;
  const darkTile = ctx.palette.bg && isDarkHex(ctx.palette.bg) ? ctx.palette.bg : '#0F172A';
  const darkTileFill = ctx.template.appearance === 'dark' ? '#020617' : darkTile;

  if (!found.length) {
    els.push(
      shape('logo_empty', box(MARGIN, CONTENT_TOP, gridW, 560), { colorRole: 'cardBg' }, { radius: ctx.template.radius }),
      text('logo_empty_text', 'No logo uploaded yet. Add one under Brand Kit › Logos and regenerate this deck.', box(MARGIN + 60, CONTENT_TOP + 240, gridW - 120, 80), {
        fontSize: 13,
        colorRole: 'muted',
        align: 'center',
      })
    );
  }

  found.forEach((v, i) => {
    const x = MARGIN + (i % cols) * (tileW + GAP);
    const y = CONTENT_TOP + Math.floor(i / cols) * (tileH + 80);
    els.push(
      shape(`logo_tile_${i}`, box(x, y, tileW, tileH), { color: v.dark ? darkTileFill : '#F8FAFC' }, {
        radius: ctx.template.radius,
        stroke: SWATCH_STROKE[v.dark ? 'dark' : 'light'],
      }),
      image(`logo_${i}`, v.media, box(x + 40, y + 36, tileW - 80, tileH - 72), { alt: v.label, role: 'logo_variant' }),
      text(`logo_label_${i}`, v.label, box(x, y + tileH + 14, tileW, 32), {
        fontSize: TYPE.caption,
        bold: true,
        colorRole: 'muted',
        role: 'caption',
      })
    );
  });

  const rulesX = MARGIN + gridW + 80;
  const rulesW = CONTENT_W - gridW - 80;
  const clearSpace = clip(usage.logoClearSpace, 80) || '1.5x cap height';
  const minSize = Number(usage.logoMinSizePx) || 24;
  const doNot = [
    ...(Array.isArray(usage.doNot) ? usage.doNot : []),
    'Stretch, rotate, or recolor the logo.',
    'Place it on busy or low-contrast backgrounds.',
  ];
  els.push(
    ...labelledBlock(ctx, 'logo_rules', {
      x: rulesX,
      y: CONTENT_TOP,
      w: rulesW,
      h: 260,
      label: 'Clear space & size',
      body: `Clear space — ${clearSpace} on every side.\nMinimum size — ${minSize}px tall on screen.`,
    }),
    ...labelledBlock(ctx, 'logo_donts', {
      x: rulesX,
      y: CONTENT_TOP + 260 + GAP,
      w: rulesW,
      h: 920 - (CONTENT_TOP + 260 + GAP),
      label: 'Avoid',
      body: bulletList(doNot, 3, 60),
    })
  );

  return {
    order: 4,
    contentType: 'grid',
    layoutId: 'brand_guideline_logos',
    content: { title: 'Logo system' },
    elements: slideDoc(els),
  };
}

// ── 5. Typography ─────────────────────────────────────────────────────

function weightLabel(weight) {
  const w = Number(weight) || 400;
  if (w >= 700) return `Bold ${w}`;
  if (w >= 600) return `Semibold ${w}`;
  if (w >= 500) return `Medium ${w}`;
  return `Regular ${w}`;
}

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

function buildTypography(ctx) {
  const fonts = ctx.kit.data?.fonts || {};
  const els = frame(ctx, 5, 'Typography', 'Typography');
  const levels = [
    { key: 'heading', label: 'Heading', role: 'heading', sample: ctx.kit.name || 'Headline in the brand voice', min: 24, max: 40, fallback: 40 },
    { key: 'subheading', label: 'Subheading', role: 'subheading', sample: 'Clear hierarchy guides the reader through every page.', min: 15, max: 22, fallback: 20 },
    { key: 'body', label: 'Body', role: 'body', sample: 'Body copy carries the detail. Keep lines short, contrast high, and spacing generous.', min: 11, max: 15, fallback: 14 },
  ];

  const rowH = 200;
  const labelW = 440;
  levels.forEach((level, i) => {
    const face = fonts[level.key] || {};
    const family = face.family || ctx.tokens.fonts?.[level.key] || 'Inter';
    const weight = Number(face.weight) || (level.key === 'heading' ? 700 : level.key === 'subheading' ? 600 : 400);
    const size = Number(face.sizePx) || level.fallback;
    const lh = Number(face.lineHeight) || 1.3;
    const y = CONTENT_TOP + i * (rowH + 20);
    const pad = inset(ctx);

    els.push(...panel(ctx, `type_panel_${level.key}`, MARGIN, y, CONTENT_W, rowH));
    els.push(
      text(`type_label_${level.key}`, level.label.toUpperCase(), box(MARGIN + pad, y + (pad ? 30 : 8), labelW, 32), {
        fontSize: TYPE.label,
        bold: true,
        colorRole: accentInk(ctx),
        role: 'caption',
      }),
      text(`type_family_${level.key}`, family, box(MARGIN + pad, y + (pad ? 70 : 48), labelW, 44), {
        fontSize: TYPE.subhead,
        bold: true,
        role: 'subheading',
      }),
      text(`type_spec_${level.key}`, `${weightLabel(weight)}  ·  ${size}px  ·  ${lh} line height`, box(MARGIN + pad, y + (pad ? 118 : 96), labelW, 32), {
        fontSize: TYPE.caption,
        colorRole: 'muted',
        role: 'caption',
      })
    );

    const sampleSize = clamp(size, level.min, level.max);
    const sampleX = MARGIN + pad + labelW + 60;
    const sampleW = CONTENT_W - pad * 2 - labelW - 60;
    els.push(
      text(`type_sample_${level.key}`, clip(level.sample, 140), box(sampleX, y + (pad ? 24 : 4), sampleW, rowH - (pad ? 48 : 8)), {
        fontSize: sampleSize,
        fontWeight: weight >= 600 ? 700 : 400,
        bold: weight >= 600,
        fontFamily: family,
        lineHeight: clamp(lh, 1.05, 1.6),
        role: level.role,
      })
    );
  });

  return {
    order: 5,
    contentType: 'bullet_list',
    layoutId: 'brand_guideline_typography',
    content: { title: 'Typography' },
    elements: slideDoc(els),
  };
}

// ── 6. Buttons ────────────────────────────────────────────────────────

function buttonSpec(btn) {
  const border = btn.borderWidthPx > 0 ? `${btn.borderWidthPx}px ${btn.border.toUpperCase()}` : 'None';
  return [
    `Fill — ${btn.background.toUpperCase()}`,
    `Label — ${btn.text.toUpperCase()}`,
    `Border — ${border}`,
    `Corner radius — ${btn.borderRadiusPx}px`,
    `Padding — ${btn.paddingYPx} × ${btn.paddingXPx}px`,
    `Label type — ${weightLabel(btn.fontWeight)}, ${btn.fontSizePx}px`,
  ].join('\n');
}

function buildButtons(ctx) {
  const buttons = ctx.tokens.buttons || {};
  const els = frame(ctx, 6, 'Components', 'Buttons');
  const colW = (CONTENT_W - GAP) / 2;
  const h = 920 - CONTENT_TOP;
  const pad = inset(ctx);

  [
    { key: 'primary', label: 'Primary button', usage: 'The main action on a page or slide. Use once per view.' },
    { key: 'secondary', label: 'Secondary button', usage: 'Supporting actions next to a primary button.' },
  ].forEach((def, i) => {
    const btn = buttons[def.key];
    if (!btn) return;
    const x = MARGIN + i * (colW + GAP);
    els.push(...panel(ctx, `btn_panel_${def.key}`, x, CONTENT_TOP, colW, h));
    els.push(
      text(`btn_label_${def.key}`, def.label.toUpperCase(), box(x + pad, CONTENT_TOP + pad, colW - pad * 2, 32), {
        fontSize: TYPE.label,
        bold: true,
        colorRole: accentInk(ctx),
        role: 'caption',
      })
    );
    // Preview drawn as a shape only: the editor would recolor a label sitting on the fill.
    const previewW = 360;
    const previewH = 96;
    els.push(
      shape(`btn_preview_${def.key}`, box(x + pad, CONTENT_TOP + pad + 56, previewW, previewH), { color: btn.background }, {
        radius: Math.max(btn.borderRadiusPx, 1),
        stroke: btn.borderWidthPx > 0 ? btn.border : null,
        strokeWidth: btn.borderWidthPx,
        layer: 2,
      }),
      text(`btn_name_${def.key}`, clip(btn.label || def.label, 40), box(x + pad + previewW + 32, CONTENT_TOP + pad + 64, colW - pad * 2 - previewW - 32, 52), {
        fontSize: TYPE.subhead,
        bold: true,
        role: 'subheading',
      }),
      text(`btn_usage_${def.key}`, def.usage, box(x + pad + previewW + 32, CONTENT_TOP + pad + 118, colW - pad * 2 - previewW - 32, 64), {
        fontSize: TYPE.caption,
        colorRole: 'muted',
        lineHeight: 1.45,
        role: 'caption',
      }),
      text(`btn_spec_${def.key}`, buttonSpec(btn), box(x + pad, CONTENT_TOP + pad + 200, colW - pad * 2, h - pad * 2 - 200), {
        fontSize: TYPE.body,
        lineHeight: 1.7,
      })
    );
  });

  return {
    order: 6,
    contentType: 'grid',
    layoutId: 'brand_guideline_ui_buttons',
    content: { title: 'Buttons' },
    elements: slideDoc(els),
  };
}

// ── 7. Imagery ────────────────────────────────────────────────────────

function buildImagery(ctx) {
  const data = ctx.kit.data || {};
  const els = frame(ctx, 7, 'Imagery', 'Imagery & data');
  const leftW = 760;
  const style = clip(data.imageStyle, 160) || 'Natural light, real people and products, uncluttered compositions with brand colors as accents.';

  els.push(
    ...labelledBlock(ctx, 'img_style', {
      x: MARGIN,
      y: CONTENT_TOP,
      w: leftW,
      h: 330,
      label: 'Photography style',
      body: style,
      bodySize: 15,
      bodyRole: 'subheading',
      lineHeight: 1.45,
    })
  );

  const chartColors = (ctx.tokens.brand?.chartColors || []).length
    ? ctx.tokens.brand.chartColors
    : [ctx.palette.primary, ctx.palette.secondary, ctx.palette.accent].filter(Boolean);
  const chartY = CONTENT_TOP + 330 + GAP;
  const pad = inset(ctx);
  els.push(
    ...panel(ctx, 'chart_panel', MARGIN, chartY, leftW, 920 - chartY),
    text('chart_label', 'CHART COLORS', box(MARGIN + pad, chartY + pad, leftW - pad * 2, 32), {
      fontSize: TYPE.label,
      bold: true,
      colorRole: accentInk(ctx),
      role: 'caption',
    })
  );
  const unique = [...new Set(chartColors.map((c) => String(c).toUpperCase()))].slice(0, 6);
  const dot = 72;
  const step = (leftW - pad * 2) / 6;
  unique.forEach((hex, i) => {
    const x = MARGIN + pad + i * step;
    els.push(
      shape(`chart_dot_${i}`, box(x, chartY + pad + 52, dot, dot), { color: hex }, {
        shape: 'circle',
        stroke: SWATCH_STROKE[ctx.template.appearance],
        layer: 2,
      }),
      text(`chart_hex_${i}`, hex, box(x - 20, chartY + pad + 52 + dot + 12, dot + 40, 28), {
        fontSize: 9,
        colorRole: 'muted',
        align: 'center',
        role: 'caption',
      })
    );
  });

  const media = ctx.kit.media || [];
  const visuals = [
    ...media.filter((m) => m.kind === 'mockup' && m.url),
    ...media.filter((m) => m.kind === 'photo' && m.url),
  ].slice(0, 2);
  const rightX = MARGIN + leftW + GAP;
  const rightW = CONTENT_W - leftW - GAP;
  const rightH = 920 - CONTENT_TOP;

  if (!visuals.length) {
    els.push(
      shape('visual_empty', box(rightX, CONTENT_TOP, rightW, rightH), { colorRole: 'cardBg' }, { radius: ctx.template.radius }),
      text('visual_empty_text', 'Add photos or mockups to the brand kit to show imagery examples here.', box(rightX + 60, CONTENT_TOP + rightH / 2 - 40, rightW - 120, 80), {
        fontSize: 13,
        colorRole: 'muted',
        align: 'center',
      })
    );
  } else {
    const each = (rightH - GAP * (visuals.length - 1)) / visuals.length;
    visuals.forEach((m, i) => {
      els.push(
        image(`visual_${i}`, m, box(rightX, CONTENT_TOP + i * (each + GAP), rightW, each), {
          fit: 'cover',
          radius: ctx.template.radius,
          alt: m.name || 'Brand imagery',
        })
      );
    });
  }

  return {
    order: 7,
    contentType: 'image+text',
    layoutId: 'brand_guideline_imagery',
    content: { title: 'Imagery & data', imageStyle: data.imageStyle },
    elements: slideDoc(els),
  };
}

// ── 8. Usage / governance ─────────────────────────────────────────────

function buildUsage(ctx) {
  const data = ctx.kit.data || {};
  const voice = data.voice || {};
  const usage = data.usage || {};
  const els = frame(ctx, 8, 'Usage', 'Using the brand');
  const colW = (CONTENT_W - GAP) / 2;
  const h = 560;

  const always = [
    'Use the approved logo files from this brand kit.',
    'Keep text-to-background contrast at 4.5:1 or higher.',
    'Use the brand fonts and type scale in this guide.',
    voice.tone ? `Write in a ${clip(voice.tone, 60).toLowerCase()} voice.` : null,
  ];
  const never = [
    ...(Array.isArray(usage.doNot) ? usage.doNot : []),
    'Introduce colors outside the palette.',
    'Alter, distort, or recreate the logo.',
  ];

  els.push(
    ...labelledBlock(ctx, 'always', { x: MARGIN, y: CONTENT_TOP, w: colW, h, label: 'Always', body: bulletList(always, 5, 70), lineHeight: 1.55 }),
    ...labelledBlock(ctx, 'never', {
      x: MARGIN + colW + GAP,
      y: CONTENT_TOP,
      w: colW,
      h,
      label: 'Never',
      body: bulletList(never, 5, 70),
      lineHeight: 1.55,
    })
  );

  els.push(
    text('closing', `Questions about using the ${clip(ctx.kit.name, 60)} brand? Contact your brand or marketing team.`, box(MARGIN, CONTENT_TOP + h + 60, CONTENT_W, 48), {
      fontSize: TYPE.body,
      colorRole: 'muted',
    })
  );

  return {
    order: 8,
    contentType: 'closing',
    layoutId: 'brand_guideline_governance',
    content: { title: 'Using the brand', bullets: [...always, ...never].filter(Boolean) },
    elements: slideDoc(els),
  };
}

/**
 * @param {object} kit Brand kit with presigned media.
 * @param {object} deckTokens Theme tokens from deckThemeTokensForTemplate.
 * @param {string} templateId One of GUIDELINE_TEMPLATE_IDS.
 */
function buildGuidelineSlides(kit, deckTokens, templateId) {
  const ctx = {
    kit,
    tokens: deckTokens,
    palette: deckTokens.palette || {},
    template: getGuidelineTemplate(templateId),
  };
  return [
    buildCover(ctx),
    buildVoice(ctx),
    buildColors(ctx),
    buildLogos(ctx),
    buildTypography(ctx),
    buildButtons(ctx),
    buildImagery(ctx),
    buildUsage(ctx),
  ];
}

function listGuidelineTemplates() {
  return GUIDELINE_TEMPLATE_IDS.map((id) => {
    const { name, description, appearance } = GUIDELINE_TEMPLATES[id];
    return { id, name, description, appearance };
  });
}

module.exports = {
  CANVAS,
  DEFAULT_GUIDELINE_TEMPLATE_ID,
  GUIDELINE_TEMPLATE_IDS,
  buildGuidelineSlides,
  deckThemeTokensForTemplate,
  getGuidelineTemplate,
  listGuidelineTemplates,
};
