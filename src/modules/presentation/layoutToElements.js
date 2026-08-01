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
  card: ['cards', 'features', 'items'],
  feature: ['features', 'cards'],
  item: ['items'],
  column: ['columns'],
};

const INDEXED_SLOT_RE = /^(stat|metric|member|milestone|card|feature|item|column)_(\d+)$/;
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
  if (id === 'caption') return { fontSize: 14, bold: false, align: 'left' };
  if (id === 'attribution') return { fontSize: 16, bold: false, align: centerable };
  if (id.includes('quote')) return { fontSize: 28, bold: false, align: centerable };
  if (id.includes('subtitle')) return { fontSize: 24, bold: false, align: centerable };
  if (id === 'left_title' || id === 'right_title') return { fontSize: 24, bold: true, align: 'left' };
  if (id.includes('title')) return { fontSize: 42, bold: true, align: centerable };
  return { fontSize: 18, bold: false, align: 'left' };
}

/**
 * Compile a DECK_LAYOUT schema + slide content into freeform canvas elements.
 * @param {object} layoutSchema
 * @param {object} content
 * @param {object|null} imageRef
 * @param {{ width?: number, height?: number }} canvasSize
 */
function layoutSlotsToElements(layoutSchema, content = {}, imageRef = null, canvasSize = {}) {
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

    if (lower.includes('image') || lower === 'hero' || slot.fit === 'cover') {
      const url =
        imageRef?.url ||
        imageRef?.s3Url ||
        (Array.isArray(content.imageUrls) ? content.imageUrls[0] : null) ||
        null;
      elements.push({
        id: newElementId('img'),
        type: 'image',
        layer: layer++,
        placement,
        content: {
          url,
          fit: slot.fit || 'cover',
          alt: content.title || '',
        },
        role: lower.includes('image') ? 'image' : slotId,
      });
      continue;
    }

    if (lower === 'accent' || lower === 'band' || lower === 'axis' || slot.fit === 'fill') {
      elements.push({
        id: newElementId('shp'),
        type: 'shape',
        layer: layer++,
        placement,
        content: {
          shape: 'rect',
          fill: lower === 'axis' ? 'secondary' : 'primary',
        },
        role: lower === 'accent' ? 'accent' : slotId,
      });
      continue;
    }

    if (lower === 'table' && tableRowsOf(content).length) {
      elements.push({
        id: newElementId('tbl'),
        type: 'table',
        layer: layer++,
        placement,
        content: { rows: tableRowsOf(content) },
        role: 'table',
      });
      continue;
    }

    if (lower.includes('chart') || lower.includes('graph')) {
      elements.push({
        id: newElementId('cht'),
        type: 'chart',
        layer: layer++,
        placement,
        content: {
          chartType: content.chart?.type || 'bar',
          series: content.chart?.series || content.chart?.data || [],
          labels: content.chart?.labels || [],
        },
        role: 'chart',
      });
      continue;
    }

    const text = textForSlot(slotId, content);
    const isTitle = lower.includes('title') && !lower.includes('subtitle');
    const isMainTitle = lower === 'title' || lower === 'headline';
    const style = styleForSlot(slotId, layoutSchema);
    elements.push({
      id: newElementId('txt'),
      type: 'text',
      layer: layer++,
      placement,
      content: {
        text: text || (isMainTitle ? content.title || '' : ''),
        fontSize: style.fontSize,
        bold: style.bold,
        align: style.align,
      },
      role: isTitle ? 'title' : lower.includes('subtitle') ? 'subtitle' : lower.includes('bullet') ? 'body' : slotId,
    });
  }

  // Ensure at least title if no slots
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

  if (content.notes) {
    // notes stay on slide.content; no canvas element
  }

  // If we have an image URL but the layout had no image slot, still place a side visual
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

  return {
    version: 1,
    canvas,
    elements,
  };
}

/**
 * Empty canvas for blank slides.
 */
function blankCanvas(opts = {}) {
  const withDefaultText = opts.withDefaultText === true;
  const canvas = { width: CANVAS_WIDTH, height: CANVAS_HEIGHT };
  const elements = [];
  if (withDefaultText) {
    elements.push({
      id: newElementId('txt'),
      type: 'text',
      layer: 1,
      placement: { x: 200, y: 400, width: 1520, height: 120, rotation: 0, opacity: 1 },
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

module.exports = {
  regionToPlacement,
  layoutSlotsToElements,
  blankCanvas,
  newElementId,
  injectBrandLogo,
};
