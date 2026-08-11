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

/** Where indexed slots (stat_1, member_2, …) look for their list of entries. */
const LIST_SOURCE_KEYS = {
  stat: ['stats', 'metrics'],
  metric: ['stats', 'metrics'],
  member: ['team', 'members', 'people'],
  milestone: ['milestones', 'timeline', 'events'],
  card: ['cards', 'features', 'items', 'plans', 'tiers'],
  feature: ['features', 'cards', 'plans'],
  item: ['items', 'plans', 'tiers'],
  column: ['columns'],
  plan: ['plans', 'tiers', 'pricing', 'cards'],
  price: ['plans', 'tiers', 'pricing'],
  tier: ['tiers', 'plans', 'pricing'],
};

const INDEXED_SLOT_RE = /^(stat|metric|member|milestone|card|feature|item|column|plan|price|tier)_(\d+)$/;
const CENTERED_LAYOUT_RE = /centered|thank_you|big_number|banner/;

function itemToText(item) {
  if (item === null || item === undefined) return '';
  if (typeof item === 'string') return item.trim();
  if (typeof item !== 'object') return String(item);
  const head = item.value ?? item.number ?? item.date ?? item.year ?? item.period ?? '';
  const label = item.label ?? item.title ?? item.name ?? item.heading ?? '';
  const role = item.role ?? item.subtitle ?? '';
  const detail = item.text ?? item.body ?? item.description ?? item.summary ?? '';
  return [head, label, role, detail]
    .map((part) => String(part ?? '').trim())
    .filter(Boolean)
    .join('\n');
}

function itemsToTexts(value) {
  if (!Array.isArray(value)) return [];
  return value.map(itemToText).filter(Boolean);
}

function bulletBlock(list) {
  return list.map((line) => `• ${line}`).join('\n');
}

function bulletsOf(content) {
  return itemsToTexts(content.bullets);
}

function listForKind(kind, content) {
  const keys = LIST_SOURCE_KEYS[kind] || [`${kind}s`];
  for (const key of keys) {
    const list = itemsToTexts(content[key]);
    if (list.length) return list;
  }
  return [];
}

function primaryStat(content) {
  const raw = content.stat || (Array.isArray(content.stats) ? content.stats[0] : null);
  if (!raw) return { value: '', label: '' };
  if (typeof raw === 'string') return { value: raw, label: content.subtitle || '' };
  return {
    value: String(raw.value ?? raw.number ?? '').trim(),
    label: String(raw.label ?? raw.title ?? raw.text ?? content.subtitle ?? '').trim(),
  };
}

function sideOf(content, side) {
  const src = content[side] || content.comparison?.[side] || {};
  const items = itemsToTexts(src.bullets || src.items || src.points);
  return {
    title: String(src.title || src.label || '').trim(),
    body: items.length ? bulletBlock(items) : String(src.body || src.text || '').trim(),
  };
}

function linesOf(value) {
  if (Array.isArray(value)) return itemsToTexts(value).join('\n');
  if (value && typeof value === 'object') return itemToText(value);
  return String(value || '').trim();
}

function tableRowsOf(content) {
  const table = content.table;
  if (!table) return [];
  const rows = Array.isArray(table) ? table : Array.isArray(table.rows) ? table.rows : [];
  const headers = Array.isArray(table?.headers) ? [table.headers] : [];
  return [...headers, ...rows].map((row) => (Array.isArray(row) ? row.map((c) => String(c ?? '')) : [String(row)]));
}

function textForSlot(slotId, content = {}) {
  const id = String(slotId || '').toLowerCase();
  const bullets = bulletsOf(content);

  const indexed = id.match(INDEXED_SLOT_RE);
  if (indexed) {
    const index = Number(indexed[2]) - 1;
    return listForKind(indexed[1], content)[index] || bullets[index] || '';
  }

  switch (id) {
    case 'stat_value':
      return primaryStat(content).value;
    case 'stat_label':
      return primaryStat(content).label;
    case 'lead':
      return itemToText(content.lead) || listForKind('member', content)[0] || '';
    case 'attribution':
      return String(content.attribution || content.author || content.source || '').trim();
    case 'cta':
      return String(content.cta || content.callToAction || '').trim();
    case 'contact':
      return linesOf(content.contact);
    case 'caption':
      return String(content.caption || content.note || '').trim();
    case 'section_number':
      return String(content.sectionNumber ?? content.section_number ?? '').trim();
    case 'left_title':
      return sideOf(content, 'left').title;
    case 'right_title':
      return sideOf(content, 'right').title;
    case 'left_body':
      return sideOf(content, 'left').body;
    case 'right_body':
      return sideOf(content, 'right').body;
    case 'pros':
      return bulletBlock(itemsToTexts(content.pros).length ? itemsToTexts(content.pros) : itemsToTexts(content.left?.bullets));
    case 'cons':
      return bulletBlock(itemsToTexts(content.cons).length ? itemsToTexts(content.cons) : itemsToTexts(content.right?.bullets));
    case 'bullets_left':
    case 'bullets_right': {
      const half = Math.ceil(bullets.length / 2);
      return bulletBlock(id.endsWith('left') ? bullets.slice(0, half) : bullets.slice(half));
    }
    case 'timeline': {
      const milestones = listForKind('milestone', content);
      return bulletBlock(milestones.length ? milestones : bullets);
    }
    case 'members': {
      const members = listForKind('member', content);
      return bulletBlock(members.length ? members : bullets);
    }
    case 'left_items':
    case 'right_items': {
      const milestones = listForKind('milestone', content);
      const source = milestones.length ? milestones : bullets;
      const half = Math.ceil(source.length / 2);
      return bulletBlock(id.startsWith('left') ? source.slice(0, half) : source.slice(half));
    }
    case 'table': {
      const rows = tableRowsOf(content);
      return rows.map((row) => row.join('   |   ')).join('\n');
    }
    default:
      break;
  }

  if (id.includes('title') && !id.includes('subtitle')) return content.title || '';
  if (id.includes('subtitle')) return content.subtitle || '';
  if (id.includes('quote')) return content.quote || content.body || '';
  if (id.includes('bullet')) return bulletBlock(bullets);
  if (id.includes('body') || id.includes('text')) {
    if (content.body) return content.body;
    return bullets.length ? bulletBlock(bullets) : '';
  }
  if (id === 'accent') return '';
  return content.body || content.title || '';
}

/**
 * Typography defaults per slot so compiled decks read like a designed template
 * instead of one uniform text size.
 */
function styleForSlot(slotId, layoutSchema) {
  const id = String(slotId || '').toLowerCase();
  const centered = CENTERED_LAYOUT_RE.test(String(layoutSchema?.layout_id || '').toLowerCase());
  const centerable = centered ? 'center' : 'left';

  if (id === 'stat_value') return { fontSize: 54, bold: true, align: centerable };
  if (id === 'stat_label') return { fontSize: 22, bold: false, align: centerable };
  if (id === 'section_number') return { fontSize: 54, bold: true, align: 'left' };
  if (/^(stat|metric)_\d+$/.test(id)) return { fontSize: 30, bold: true, align: 'left' };
  if (id === 'cta') return { fontSize: 22, bold: true, align: 'center' };
  if (id === 'caption' || id === 'eyebrow') return { fontSize: 14, bold: false, align: 'left' };
  if (id === 'attribution') return { fontSize: 16, bold: false, align: centerable };
  if (id.includes('quote')) return { fontSize: 28, bold: false, align: centerable };
  if (id.includes('subtitle')) return { fontSize: 24, bold: false, align: centerable };
  if (id === 'left_title' || id === 'right_title') return { fontSize: 24, bold: true, align: 'left' };
  if (id.includes('title')) return { fontSize: 42, bold: true, align: centerable };
  return { fontSize: 18, bold: false, align: 'left' };
}

const ROLE_TYPE_SCALE = {
  heading: 'title',
  subheading: 'subtitle',
  body: 'body',
  caption: 'caption',
  eyebrow: 'caption',
  stat: 'stat',
  stat_label: 'caption',
  quote: 'subtitle',
  attribution: 'caption',
  cta: 'subtitle',
  contact: 'body',
};

function paletteColor(palette, role, fallback) {
  if (!palette || !role) return fallback;
  return palette[role] || fallback;
}

function resolveFill(shapeSpec, palette = {}) {
  if (!shapeSpec) return { type: 'solid', colorRole: 'primary' };
  if (typeof shapeSpec.fill === 'string') {
    return { type: 'solid', colorRole: shapeSpec.fill };
  }
  if (shapeSpec.fill && typeof shapeSpec.fill === 'object') {
    if (shapeSpec.fill.type === 'gradient') {
      return {
        type: 'gradient',
        direction: shapeSpec.fill.direction || '135deg',
        stops: (shapeSpec.fill.stops || []).map((stop) => ({
          color: stop.color || paletteColor(palette, stop.colorRole, '#0B1220'),
          colorRole: stop.colorRole || null,
          position: stop.position != null ? stop.position : 0,
        })),
      };
    }
    return {
      type: 'solid',
      color:
        shapeSpec.fill.color ||
        paletteColor(palette, shapeSpec.fill.colorRole || shapeSpec.fillColorRole, null),
      colorRole: shapeSpec.fill.colorRole || shapeSpec.fillColorRole || 'primary',
    };
  }
  if (shapeSpec.fillColorRole) {
    return {
      type: 'solid',
      color: paletteColor(palette, shapeSpec.fillColorRole, null),
      colorRole: shapeSpec.fillColorRole,
    };
  }
  return { type: 'solid', colorRole: 'primary' };
}

function resolveTextStyle(slot, layoutSchema, themeTokens, designTokens) {
  const slotId = slot.id || '';
  const role = String(slot.role || '').toLowerCase();
  const ty = slot.typography || {};
  const fallback = styleForSlot(slotId, layoutSchema);
  const scale = themeTokens?.typeScale || {};
  const palette = themeTokens?.palette || {};

  let fontSize = ty.fontSize;
  if (fontSize == null && role && ROLE_TYPE_SCALE[role] && scale[ROLE_TYPE_SCALE[role]] != null) {
    fontSize = scale[ROLE_TYPE_SCALE[role]];
  }
  if (fontSize == null && role === 'heading' && scale.display != null) {
    fontSize = scale.display;
  }
  if (fontSize == null) fontSize = fallback.fontSize;

  const fontWeight = ty.fontWeight != null ? Number(ty.fontWeight) : fallback.bold ? 700 : 400;
  const bold = fontWeight >= 600;
  const align = ty.align || fallback.align || 'left';
  let colorRole = ty.colorRole || null;
  if (!colorRole) {
    if (role === 'stat') colorRole = 'accent';
    else if (
      role === 'caption' ||
      role === 'attribution' ||
      role === 'eyebrow' ||
      role === 'stat_label'
    ) {
      colorRole = 'muted';
    } else if (role === 'cta') colorRole = 'primary';
    else colorRole = 'text';
  }
  if (designTokens?.textContrast === 'high' && (colorRole === 'text' || colorRole === 'muted')) {
    colorRole = 'text';
  }

  return {
    fontSize,
    bold,
    fontWeight,
    align,
    colorRole,
    color: paletteColor(palette, colorRole, null),
    letterSpacing: ty.letterSpacing != null ? ty.letterSpacing : undefined,
    lineHeight: ty.lineHeight != null ? ty.lineHeight : undefined,
  };
}

function elementRoleFromSlot(slot, slotId) {
  if (slot.role) return slot.role;
  const lower = String(slotId || '').toLowerCase();
  if (lower.includes('title') && !lower.includes('subtitle')) return 'title';
  if (lower.includes('subtitle')) return 'subtitle';
  if (lower.includes('bullet')) return 'body';
  return slotId;
}

/**
 * Apply pack/slide designTokens chrome (bg + accent bars) when layout has no background slot.
 */
function applySlideDesignTokens(elementsDoc, designTokens, themeTokens = {}) {
  if (!designTokens || typeof designTokens !== 'object') return elementsDoc;
  const doc = {
    version: elementsDoc?.version || 1,
    canvas: elementsDoc?.canvas || { width: CANVAS_WIDTH, height: CANVAS_HEIGHT },
    elements: Array.isArray(elementsDoc?.elements) ? [...elementsDoc.elements] : [],
  };
  const canvas = doc.canvas;
  const palette = themeTokens?.palette || {};
  const hasBg = doc.elements.some(
    (e) => e.role === 'background' || e.role === 'design_bg' || String(e.id || '').startsWith('bg_')
  );

  if (!hasBg && (designTokens.backgroundStyle === 'gradient' || designTokens.backgroundStyle === 'solid')) {
    const fill =
      designTokens.backgroundStyle === 'gradient'
        ? {
            type: 'gradient',
            direction: '135deg',
            stops: [
              {
                color: palette.gradientStart || palette.bg || '#0B1220',
                colorRole: 'gradientStart',
                position: 0,
              },
              {
                color: palette.gradientEnd || palette.surface || '#121A2B',
                colorRole: 'gradientEnd',
                position: 100,
              },
            ],
          }
        : {
            type: 'solid',
            color: palette.bg || '#0B1220',
            colorRole: 'bg',
          };
    doc.elements.unshift({
      id: newElementId('bg'),
      type: 'shape',
      layer: 0,
      placement: {
        x: 0,
        y: 0,
        width: canvas.width,
        height: canvas.height,
        rotation: 0,
        opacity: 1,
      },
      content: { shape: 'rect', fill },
      role: 'design_bg',
    });
  }

  const accent = designTokens.accentPosition || 'none';
  const accentColor = palette.accent || palette.primary || '#3B82F6';
  const barBase = {
    type: 'shape',
    layer: 1,
    content: {
      shape: 'rect',
      fill: { type: 'solid', color: accentColor, colorRole: 'accent' },
    },
    role: 'design_accent',
  };
  if (accent === 'left-bar') {
    doc.elements.push({
      ...barBase,
      id: newElementId('acc'),
      placement: { x: 0, y: 0, width: 8, height: canvas.height, rotation: 0, opacity: 1 },
    });
  } else if (accent === 'top-bar') {
    doc.elements.push({
      ...barBase,
      id: newElementId('acc'),
      placement: { x: 0, y: 0, width: canvas.width, height: 8, rotation: 0, opacity: 1 },
    });
  } else if (accent === 'bottom-bar') {
    doc.elements.push({
      ...barBase,
      id: newElementId('acc'),
      placement: {
        x: 0,
        y: canvas.height - 8,
        width: canvas.width,
        height: 8,
        rotation: 0,
        opacity: 1,
      },
    });
  }

  if (designTokens.overlayOpacity > 0 && designTokens.backgroundStyle === 'image') {
    doc.elements.push({
      id: newElementId('ovl'),
      type: 'shape',
      layer: 2,
      placement: {
        x: 0,
        y: 0,
        width: canvas.width,
        height: canvas.height,
        rotation: 0,
        opacity: Number(designTokens.overlayOpacity),
      },
      content: {
        shape: 'rect',
        fill: { type: 'solid', color: '#000000', colorRole: 'bg' },
      },
      role: 'design_overlay',
    });
  }

  return doc;
}

/**
 * Compile a DECK_LAYOUT schema + slide content into freeform canvas elements.
 * @param {object} layoutSchema
 * @param {object} content
 * @param {object|null} imageRef
 * @param {{ width?: number, height?: number }} canvasSize
 * @param {{ themeTokens?: object, designTokens?: object }} opts
 */
function layoutSlotsToElements(
  layoutSchema,
  content = {},
  imageRef = null,
  canvasSize = {},
  opts = {}
) {
  const themeTokens = opts.themeTokens || content.themeTokens || null;
  const designTokens = opts.designTokens || content.designTokens || null;
  const palette = themeTokens?.palette || {};

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
    const role = String(slot.role || '').toLowerCase();
    const slotLayer = slot.layer != null ? Number(slot.layer) : layer++;

    if (role === 'background' || role === 'decoration' || role === 'divider' || slot.shape) {
      const fill = resolveFill(
        slot.shape || { fillColorRole: role === 'divider' ? 'accent' : 'primary' },
        palette
      );
      elements.push({
        id: newElementId('shp'),
        type: 'shape',
        layer: slotLayer,
        placement,
        content: {
          shape: slot.shape?.type || 'rect',
          fill,
          borderRadius: slot.shape?.borderRadius,
        },
        role: role || (lower === 'accent' ? 'accent' : slotId),
      });
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
      continue;
    }

    if (lower.includes('image') || lower === 'hero' || slot.fit === 'cover' || role === 'image') {
      const url =
        imageRef?.url ||
        imageRef?.s3Url ||
        (Array.isArray(content.imageUrls) ? content.imageUrls[0] : null) ||
        null;
      elements.push({
        id: newElementId('img'),
        type: 'image',
        layer: slotLayer,
        placement,
        content: {
          url,
          fit: slot.fit || 'cover',
          alt: content.title || '',
        },
        role: 'image',
      });
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
      continue;
    }

    if (lower === 'accent' || lower === 'band' || lower === 'axis' || slot.fit === 'fill') {
      elements.push({
        id: newElementId('shp'),
        type: 'shape',
        layer: slotLayer,
        placement,
        content: {
          shape: 'rect',
          fill: {
            type: 'solid',
            colorRole: lower === 'axis' ? 'secondary' : 'primary',
            color: paletteColor(palette, lower === 'axis' ? 'secondary' : 'primary', null),
          },
        },
        role: lower === 'accent' ? 'accent' : slotId,
      });
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
      continue;
    }

    if ((lower === 'table' || role === 'table') && tableRowsOf(content).length) {
      elements.push({
        id: newElementId('tbl'),
        type: 'table',
        layer: slotLayer,
        placement,
        content: { rows: tableRowsOf(content) },
        role: 'table',
      });
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
      continue;
    }

    if (lower.includes('chart') || lower.includes('graph') || role === 'chart') {
      const brandChartColors = themeTokens?.brand?.chartColors;
      elements.push({
        id: newElementId('cht'),
        type: 'chart',
        layer: slotLayer,
        placement,
        content: {
          chartType: content.chart?.type || 'bar',
          series: content.chart?.series || content.chart?.data || [],
          labels: content.chart?.labels || [],
          colors:
            (Array.isArray(content.chart?.colors) && content.chart.colors.length
              ? content.chart.colors
              : null) ||
            (Array.isArray(content.colors) && content.colors.length ? content.colors : null) ||
            (Array.isArray(brandChartColors) && brandChartColors.length ? brandChartColors : []),
        },
        role: 'chart',
      });
      if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
      continue;
    }

    const text = textForSlot(slotId, content);
    const isMainTitle = lower === 'title' || lower === 'headline' || role === 'heading';
    const style = resolveTextStyle(slot, layoutSchema, themeTokens, designTokens);
    const textContent = {
      text: text || (isMainTitle ? content.title || '' : '') || slot.placeholder_text || '',
      fontSize: style.fontSize,
      bold: style.bold,
      fontWeight: style.fontWeight,
      align: style.align,
    };
    if (style.color) textContent.color = style.color;
    if (style.colorRole) textContent.colorRole = style.colorRole;
    if (style.letterSpacing != null) textContent.letterSpacing = style.letterSpacing;
    if (style.lineHeight != null) textContent.lineHeight = style.lineHeight;

    elements.push({
      id: newElementId('txt'),
      type: 'text',
      layer: slotLayer,
      placement,
      content: textContent,
      role: elementRoleFromSlot(slot, slotId),
    });
    if (slot.layer == null) layer = Math.max(layer, slotLayer + 1);
  }

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

  const hasImageEl = elements.some((e) => e.type === 'image');
  const imageUrl =
    imageRef?.url ||
    imageRef?.s3Url ||
    (Array.isArray(content.imageUrls) ? content.imageUrls[0] : null) ||
    null;
  if (imageUrl && !hasImageEl) {
    elements.push({
      id: newElementId('img'),
      type: 'image',
      layer: layer++,
      placement: {
        x: Math.round(canvas.width * 0.55),
        y: Math.round(canvas.height * 0.13),
        width: Math.round(canvas.width * 0.38),
        height: Math.round(canvas.height * 0.74),
        rotation: 0,
        opacity: 1,
      },
      content: {
        url: imageUrl,
        fit: 'cover',
        alt: content.title || '',
      },
      role: 'image',
    });
  }

  let doc = { version: 1, canvas, elements };
  doc = applySlideDesignTokens(doc, designTokens, themeTokens);
  return doc;
}

/**
 * Empty canvas for blank slides.
 */
function blankCanvas(opts = {}) {
  const withDefaultText = opts.withDefaultText === true;
  const width = Number(opts.width) > 0 ? Number(opts.width) : CANVAS_WIDTH;
  const height = Number(opts.height) > 0 ? Number(opts.height) : CANVAS_HEIGHT;
  const canvas = { width, height };
  const elements = [];
  if (withDefaultText) {
    elements.push({
      id: newElementId('txt'),
      type: 'text',
      layer: 1,
      placement: {
        x: Math.round(width * 0.1),
        y: Math.round(height * 0.37),
        width: Math.round(width * 0.8),
        height: Math.round(height * 0.11),
        rotation: 0,
        opacity: 1,
      },
      content: { text: 'Double-click to edit', fontSize: 32, bold: false, align: 'center' },
      role: 'title',
    });
  }
  return { version: 1, canvas, elements };
}

/**
 * Inject or replace a brand logo image element (title/closing slides).
 * @param {object} elementsDoc
 * @param {{ url?: string, s3Key?: string }|null} logo
 * @param {{ contentType?: string|null, force?: boolean }} opts
 */
function injectBrandLogo(elementsDoc, logo, opts = {}) {
  const doc =
    elementsDoc && typeof elementsDoc === 'object'
      ? {
          version: elementsDoc.version || 1,
          canvas: elementsDoc.canvas || { width: CANVAS_WIDTH, height: CANVAS_HEIGHT },
          elements: Array.isArray(elementsDoc.elements) ? [...elementsDoc.elements] : [],
        }
      : blankCanvas();

  const url = logo?.url || null;
  if (!url) return doc;

  const contentType = String(opts.contentType || '').toLowerCase();
  const allowTypes = new Set(['title', 'closing', 'section_divider', '']);
  if (!opts.force && contentType && !allowTypes.has(contentType)) {
    // Still update existing logo roles on any slide
    const hasLogo = doc.elements.some((e) => e?.role === 'logo');
    if (!hasLogo) return doc;
  }

  const canvas = doc.canvas || { width: CANVAS_WIDTH, height: CANVAS_HEIGHT };
  const logoPlacement = {
    x: Math.round(canvas.width * 0.04),
    y: Math.round(canvas.height * 0.04),
    width: Math.round(canvas.width * 0.14),
    height: Math.round(canvas.height * 0.1),
    rotation: 0,
    opacity: 1,
  };

  const existingIdx = doc.elements.findIndex((e) => e?.role === 'logo');
  const logoEl = {
    id: existingIdx >= 0 ? doc.elements[existingIdx].id : newElementId('logo'),
    type: 'image',
    layer: existingIdx >= 0 ? doc.elements[existingIdx].layer : 99,
    placement:
      existingIdx >= 0 && doc.elements[existingIdx].placement
        ? doc.elements[existingIdx].placement
        : logoPlacement,
    content: {
      url,
      s3Key: logo.s3Key || null,
      fit: 'contain',
      alt: 'Brand logo',
    },
    role: 'logo',
  };

  if (existingIdx >= 0) {
    doc.elements[existingIdx] = logoEl;
  } else if (!contentType || allowTypes.has(contentType) || opts.force) {
    doc.elements.push(logoEl);
  }

  return doc;
}

/**
 * Rebind generated slide content into an existing canvas by element role.
 * Preserves placement/chrome; updates text/image payloads in place.
 */
function rebindContentToElements(elementsDoc, content = {}, imageRef = null) {
  const doc = {
    version: elementsDoc?.version || 1,
    canvas: elementsDoc?.canvas || { width: CANVAS_WIDTH, height: CANVAS_HEIGHT },
    elements: Array.isArray(elementsDoc?.elements)
      ? elementsDoc.elements.map((el) => ({ ...el, content: el.content ? { ...el.content } : {} }))
      : [],
  };

  const imageUrl =
    imageRef?.url ||
    imageRef?.s3Url ||
    (Array.isArray(content.imageUrls) ? content.imageUrls[0] : null) ||
    null;

  for (const el of doc.elements) {
    const role = String(el.role || '').toLowerCase();
    const id = String(el.id || '').toLowerCase();
    const roleOrId = role || id;

    if (el.type === 'text' || el.type === 'textbox') {
      const text = textForSlot(roleOrId, content);
      if (text != null && String(text).length) {
        el.content = { ...(el.content || {}), text: String(text) };
      } else if (role === 'title' || role === 'heading' || role === 'headline') {
        if (content.title) el.content = { ...(el.content || {}), text: String(content.title) };
      } else if (role === 'subtitle' || role === 'subheading') {
        if (content.subtitle) el.content = { ...(el.content || {}), text: String(content.subtitle) };
      } else if (role === 'body' || role === 'bullets') {
        const bullets = bulletsOf(content);
        const body =
          content.body || (bullets.length ? bulletBlock(bullets) : '');
        if (body) el.content = { ...(el.content || {}), text: String(body) };
      }
    }

    if (el.type === 'table' && (role === 'table' || id.includes('table'))) {
      const rows = tableRowsOf(content);
      if (rows.length) el.content = { ...(el.content || {}), rows };
    }

    if (
      el.type === 'image' &&
      role !== 'logo' &&
      imageUrl &&
      (role === 'image' || !role || id.includes('image') || id.includes('hero'))
    ) {
      el.content = {
        ...(el.content || {}),
        url: imageUrl,
        s3Key: imageRef?.s3Key || el.content?.s3Key || null,
        fit: el.content?.fit || 'cover',
        alt: content.title || el.content?.alt || '',
      };
    }
  }

  return doc;
}

function elementsHaveRebindRoles(elementsDoc) {
  const els = Array.isArray(elementsDoc?.elements) ? elementsDoc.elements : [];
  return els.some((el) => {
    const role = String(el.role || '').toLowerCase();
    return (
      role === 'title' ||
      role === 'heading' ||
      role === 'headline' ||
      role === 'subtitle' ||
      role === 'subheading' ||
      role === 'body' ||
      role === 'image' ||
      role === 'bullets' ||
      role === 'caption' ||
      role === 'quote' ||
      role === 'cta'
    );
  });
}

module.exports = {
  regionToPlacement,
  layoutSlotsToElements,
  rebindContentToElements,
  elementsHaveRebindRoles,
  applySlideDesignTokens,
  blankCanvas,
  newElementId,
  injectBrandLogo,
};
