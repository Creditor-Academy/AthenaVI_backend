const AppError = require('../../shared/utils/AppError');
const s3Service = require('../s3/s3.service');
const dao = require('./graphics.dao');
const { validateSvgBuffer } = require('./svgValidate.service');
const { searchGraphics } = require('./graphics.search');
const { newElementId } = require('../presentation/layoutToElements');
const { MAX_ELEMENTS_PER_SLIDE } = require('../presentation/presentation.constants');
const svglClient = require('./svgl.client');

function parseStringList(value) {
  if (Array.isArray(value)) {
    return value.map((v) => String(v).trim()).filter(Boolean);
  }
  if (typeof value === 'string' && value.trim()) {
    return value.split(',').map((v) => v.trim()).filter(Boolean);
  }
  return [];
}

function parseBool(value, fallback = false) {
  if (value == null || value === '') return fallback;
  if (typeof value === 'boolean') return value;
  const s = String(value).toLowerCase();
  if (s === 'true' || s === '1') return true;
  if (s === 'false' || s === '0') return false;
  return fallback;
}

const PRESIGN_TTL_SEC = 3600;

async function resolveGraphicUrl(s3Key, fallbackUrl) {
  if (s3Key) {
    try {
      return await s3Service.getPresignedGetUrl(s3Key, PRESIGN_TTL_SEC);
    } catch {
      /* fall through */
    }
  }
  if (fallbackUrl) return fallbackUrl;
  if (s3Key) return s3Service.buildPublicUrl(s3Key);
  return '';
}

function serializeBase(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    description: row.description || '',
    fileUrl: row.fileUrl,
    previewUrl: row.previewUrl,
    s3Key: row.s3Key || null,
    previewS3Key: row.previewS3Key || null,
    type: row.type,
    category: row.category,
    tags: row.tags || [],
    style: row.style || '',
    moods: row.moods || [],
    usage: row.usage || [],
    colorMode: row.colorMode,
    containsText: Boolean(row.containsText),
    status: row.status,
    createdBy: row.createdBy,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

/** Public API shape with fresh presigned URLs (private S3 buckets cannot use raw public URLs). */
async function serialize(row) {
  const base = serializeBase(row);
  if (!base) return null;
  const [fileUrl, previewUrl] = await Promise.all([
    resolveGraphicUrl(row.s3Key, row.fileUrl),
    resolveGraphicUrl(row.previewS3Key || row.s3Key, row.previewUrl || row.fileUrl),
  ]);
  return {
    ...base,
    fileUrl,
    previewUrl: previewUrl || fileUrl,
  };
}

async function serializeMany(rows = []) {
  return Promise.all((rows || []).map((row) => serialize(row)));
}

function metadataFromBody(body = {}) {
  const next = {};
  if (body.name != null) next.name = String(body.name).trim();
  if (body.description !== undefined) next.description = body.description ? String(body.description).trim() : null;
  if (body.type) next.type = body.type;
  if (body.category) next.category = String(body.category).trim();
  if (body.tags !== undefined) next.tags = parseStringList(body.tags);
  if (body.style !== undefined) next.style = body.style ? String(body.style).trim() : null;
  if (body.moods !== undefined) next.moods = parseStringList(body.moods);
  if (body.usage !== undefined) next.usage = parseStringList(body.usage);
  if (body.colorMode) next.colorMode = body.colorMode;
  if (body.containsText !== undefined) next.containsText = parseBool(body.containsText);
  return next;
}

async function uploadOriginalAndPreview(id, buffer) {
  const originalKey = `presentations/_system/graphics/${id}/original.svg`;
  const previewKey = `presentations/_system/graphics/${id}/preview.svg`;
  const original = await s3Service.uploadFileToKey(buffer, originalKey, 'image/svg+xml');
  const preview = await s3Service.uploadFileToKey(buffer, previewKey, 'image/svg+xml');
  return {
    s3Key: original.key,
    fileUrl: original.url,
    previewS3Key: preview.key,
    previewUrl: preview.url,
  };
}

async function createFromUpload({ file, body, userId }) {
  if (!file?.buffer) throw new AppError('SVG file is required', 400);
  validateSvgBuffer(file.buffer, { mimeType: file.mimetype });

  const id = require('crypto').randomBytes(12).toString('hex');
  const stored = await uploadOriginalAndPreview(id, file.buffer);
  const meta = metadataFromBody(body);
  const type = meta.type || 'decorative';
  const defaultUsage =
    type === 'icon' ? ['bullet', 'list', 'editor', 'content'] : ['editor'];

  const row = await dao.create({
    id,
    name: meta.name || (file.originalname || 'Untitled graphic').replace(/\.svg$/i, ''),
    description: meta.description || null,
    type,
    category: meta.category || (type === 'icon' ? 'icons' : 'ornaments'),
    tags: meta.tags || [],
    style: meta.style || null,
    moods: meta.moods || [],
    usage: meta.usage?.length ? meta.usage : defaultUsage,
    colorMode: meta.colorMode || (type === 'icon' ? 'recolorable' : 'fixed'),
    containsText: Boolean(meta.containsText),
    status: 'draft',
    createdBy: userId,
    ...stored,
  });
  return serialize(row);
}

async function listAdmin(query = {}) {
  const page = Number(query.page) || 1;
  const limit = Math.min(100, Number(query.limit) || 60);
  const skip = (page - 1) * limit;
  const filters = {
    q: query.q,
    category: query.category,
    type: query.type,
    style: query.style,
    mood: query.mood,
    colorMode: query.colorMode,
    status: query.status,
  };
  const [items, total] = await Promise.all([
    dao.list({ ...filters, skip, take: limit }),
    dao.count(filters),
  ]);
  return { items: await serializeMany(items), page, limit, total };
}

async function getAdmin(id) {
  const row = await dao.findById(id);
  if (!row) throw new AppError('Graphic not found', 404);
  return serialize(row);
}

async function updateMetadata(id, body) {
  const row = await dao.findById(id);
  if (!row) throw new AppError('Graphic not found', 404);
  const updated = await dao.update(id, metadataFromBody(body));
  return serialize(updated);
}

async function publish(id) {
  const row = await dao.findById(id);
  if (!row) throw new AppError('Graphic not found', 404);
  if (!row.s3Key || !row.fileUrl) throw new AppError('Graphic file is missing', 400);
  const updated = await dao.update(id, { status: 'published' });
  return serialize(updated);
}

async function unpublish(id) {
  const row = await dao.findById(id);
  if (!row) throw new AppError('Graphic not found', 404);
  const updated = await dao.update(id, { status: 'draft' });
  return serialize(updated);
}

async function archive(id) {
  const row = await dao.findById(id);
  if (!row) throw new AppError('Graphic not found', 404);
  const updated = await dao.update(id, { status: 'archived' });
  return serialize(updated);
}

async function remove(id) {
  const row = await dao.findById(id);
  if (!row) throw new AppError('Graphic not found', 404);
  try {
    if (row.s3Key) await s3Service.deleteFile(row.s3Key);
    if (row.previewS3Key && row.previewS3Key !== row.s3Key) {
      await s3Service.deleteFile(row.previewS3Key);
    }
  } catch {
    /* best-effort S3 cleanup */
  }
  await dao.remove(id);
  return { id };
}

async function listPublished(query = {}) {
  const page = Number(query.page) || 1;
  const limit = Math.min(100, Number(query.limit) || 60);
  const skip = (page - 1) * limit;
  const filters = {
    q: query.q,
    category: query.category,
    type: query.type,
    style: query.style,
    mood: query.mood,
    colorMode: query.colorMode,
    status: 'published',
  };
  const [items, total] = await Promise.all([
    dao.list({ ...filters, skip, take: limit }),
    dao.count(filters),
  ]);
  return { items: await serializeMany(items), page, limit, total };
}

async function getPublished(id) {
  const row = await dao.findById(id);
  if (!row || row.status !== 'published') throw new AppError('Graphic not found', 404);
  return serialize(row);
}

async function searchPublished(intent = {}, theme = null) {
  const published = await dao.listPublished();
  const ranked = searchGraphics(published, intent, theme);
  return serializeMany(ranked);
}

function deriveGraphicNeed({ content = {}, elements = [], visualNeed } = {}) {
  const els = Array.isArray(elements) ? elements : [];
  const hasChart = els.some((e) => e?.type === 'chart' || e?.role === 'chart');
  const hasTable = els.some((e) => e?.type === 'table');
  const hasImage = els.some((e) => e?.type === 'image' && e?.role !== 'logo');
  const bullets = Array.isArray(content.bullets) ? content.bullets : [];
  const body = String(content.body || content.description || '');
  const denseText = bullets.length >= 6 || body.length > 600;
  const vn = String(visualNeed || content.visual_need || content.visualNeed || '').toLowerCase();

  if (hasChart || hasTable || denseText) return 'none';
  if (vn === 'chart' || vn === 'diagram_template' || vn === 'path_b') return 'none';
  if (hasImage && bullets.length >= 4) return 'none';
  if (!hasImage && bullets.length <= 3) return 'recommended';
  if (!hasImage) return 'optional';
  return 'optional';
}

function pickCornerPlacement(canvas = {}, index = 0) {
  const w = canvas.width || 1920;
  const h = canvas.height || 1080;
  const size = Math.round(Math.min(w, h) * 0.22);
  const corners = [
    { x: w - size - 32, y: 28 },
    { x: 28, y: h - size - 28 },
    { x: w - size - 32, y: h - size - 28 },
  ];
  const pos = corners[index % corners.length];
  return {
    x: pos.x,
    y: pos.y,
    width: size,
    height: size,
    rotation: 0,
    opacity: 0.92,
  };
}

const LIST_ICON_SLOT_RE = /^(BULLET|ITEM)_\d+$/i;
const LIST_CARD_TITLE_RE = /^CARD_\d+_TITLE$/i;
const LIST_ROW_TITLE_RE = /^ROW_\d+_TITLE$/i;
const LIST_STEP_TITLE_RE = /^(STEP|step)_\d+_TITLE$/i;
const LIST_COL_TITLE_RE = /^COL_\d+_TITLE$/i;
const LIST_IMAGE_LABEL_RE = /^IMAGE_\d+_LABEL$/i;
const LIST_ICON_SIZE = 48;
const LIST_ICON_GAP = 16;

function slotIndexFromId(slotId) {
  const m = String(slotId || '').match(/_(\d+)/);
  return m ? Number(m[1]) : 0;
}

function isListIconTitleSlot(slotId) {
  const sid = String(slotId || '');
  return (
    LIST_ICON_SLOT_RE.test(sid) ||
    LIST_CARD_TITLE_RE.test(sid) ||
    LIST_ROW_TITLE_RE.test(sid) ||
    LIST_STEP_TITLE_RE.test(sid) ||
    LIST_COL_TITLE_RE.test(sid) ||
    LIST_IMAGE_LABEL_RE.test(sid)
  );
}

function findListIconTargets(elementsDoc) {
  const elements = Array.isArray(elementsDoc?.elements) ? elementsDoc.elements : [];
  const targets = elements
    .filter((el) => {
      if (!el || (el.type !== 'text' && el.type !== 'textbox')) return false;
      return isListIconTitleSlot(el.slotId);
    })
    .sort((a, b) => slotIndexFromId(a.slotId) - slotIndexFromId(b.slotId));

  return targets.slice(0, 5);
}

function textFromTargetElement(el) {
  const c = el?.content || {};
  if (typeof c.text === 'string' && c.text.trim()) return c.text.trim();
  if (Array.isArray(c.runs) && c.runs.length) {
    return c.runs.map((r) => String(r?.text || '')).join('').trim();
  }
  return '';
}

function listItemTexts(content = {}) {
  const bullets = Array.isArray(content.bullets) ? content.bullets : [];
  if (bullets.length >= 2) {
    return bullets.map((raw) => {
      if (raw == null) return '';
      if (typeof raw === 'string') return raw;
      return String(raw.topic || raw.title || raw.text || raw.body || raw.label || '');
    });
  }
  const columns = Array.isArray(content.columns)
    ? content.columns
    : Array.isArray(content.cards)
      ? content.cards
      : [];
  return columns.map((col) => {
    if (col == null) return '';
    if (typeof col === 'string') return col;
    return String(col.title || col.topic || col.text || col.body || col.label || '');
  });
}

function bulletTextAt(content = {}, index = 0) {
  const items = listItemTexts(content);
  return items[index] || '';
}

function tokenizeBullet(text) {
  return String(text || '')
    .toLowerCase()
    .split(/[^a-z0-9]+/i)
    .filter((t) => t.length > 2)
    .slice(0, 8);
}

function pickListIconPlacement(textEl, canvas = {}) {
  const p = textEl?.placement || {};
  const canvasW = canvas.width || 1920;
  const canvasH = canvas.height || 1080;
  const size = LIST_ICON_SIZE;
  const textX = Number(p.x) || 0;
  const textY = Number(p.y) || 0;
  const textW = Number(p.width) || size;
  const textH = Number(p.height) || size;
  const sid = String(textEl?.slotId || '');

  // Card / col / image-label titles: icon to the LEFT of the title (not up into the photo)
  if (/^(CARD|COL|ROW|STEP)_\d+_TITLE$/i.test(sid) || LIST_IMAGE_LABEL_RE.test(sid)) {
    let x = textX;
    let y = textY + Math.max(0, (textH - size) / 2);
    // If title box is wide, keep icon in the left padding of the column
    if (textW > size + 24) {
      x = textX;
    }
    x = Math.max(8, Math.min(x, canvasW - size - 8));
    y = Math.max(8, Math.min(y, canvasH - size - 8));
    return {
      x: Math.round(x),
      y: Math.round(y),
      width: size,
      height: size,
      rotation: 0,
      opacity: 1,
    };
  }

  let x = textX - LIST_ICON_GAP - size;
  if (x < 16) x = Math.min(textX + textW + LIST_ICON_GAP, canvasW - size - 16);
  x = Math.max(8, Math.min(x, canvasW - size - 8));
  let y = textY + Math.max(0, (textH - size) / 2);
  y = Math.max(8, Math.min(y, canvasH - size - 8));
  return {
    x: Math.round(x),
    y: Math.round(y),
    width: size,
    height: size,
    rotation: 0,
    opacity: 1,
  };
}

async function pickIconForBullet(bulletText, themeTokens, usedIds) {
  const appearance =
    themeTokens?.appearance === 'dark' || themeTokens?.appearance === 'light'
      ? themeTokens.appearance
      : 'light';

  // 1) SVGL only when point text confidently names a brand
  try {
    const brand = await svglClient.findBrandGraphic(bulletText, { appearance, usedIds });
    if (brand?.fileUrl) return brand;
  } catch {
    /* fall through to Graphics Library */
  }

  // 2) Graphics Library list/bullet icons (non-brand)
  try {
    const keywords = tokenizeBullet(bulletText);
    const style = themeTokens?.style || themeTokens?.vibe || '';
    const mood = themeTokens?.mood || '';
    const usageFallbacks = ['bullet', 'list', 'content', 'editor'];

    for (const usage of usageFallbacks) {
      const matches = await searchPublished(
        {
          keywords: keywords.length ? keywords : ['icon'],
          style,
          mood,
          preferredType: 'icon',
          usage,
          maxCount: 6,
        },
        themeTokens
      );
      const fresh = matches.find((g) => g?.id && !usedIds.has(g.id));
      if (fresh) return fresh;
      if (matches[0] && !usedIds.size) return matches[0];
    }

    const anyIcons = await searchPublished(
      {
        keywords: keywords.length ? keywords : ['icon'],
        preferredType: 'icon',
        maxCount: 8,
      },
      themeTokens
    );
    return anyIcons.find((g) => g?.id && !usedIds.has(g.id)) || anyIcons[0] || null;
  } catch {
    return null;
  }
}

async function injectListIconsIntoElementsDoc(elementsDoc, content = {}, themeTokens = null) {
  const targets = findListIconTargets(elementsDoc);
  if (targets.length < 2) return { doc: elementsDoc, added: 0 };

  // Prefer live canvas title text (what the user sees) over content.columns/bullets,
  // which are often empty or misaligned on image+text card layouts.
  const pointTexts = targets.map((el, i) => textFromTargetElement(el) || bulletTextAt(content, i));
  const namedCount = pointTexts.filter((t) => String(t || '').trim().length >= 2).length;
  if (namedCount < 2) {
    const fromContent = listItemTexts(content);
    if (fromContent.length < 2 || fromContent.length >= 6) {
      return { doc: elementsDoc, added: 0 };
    }
  }

  const doc =
    elementsDoc && typeof elementsDoc === 'object'
      ? {
          version: elementsDoc.version || 1,
          canvas: elementsDoc.canvas || { width: 1920, height: 1080 },
          elements: Array.isArray(elementsDoc.elements) ? [...elementsDoc.elements] : [],
        }
      : { version: 1, canvas: { width: 1920, height: 1080 }, elements: [] };

  // Avoid duplicating icons on regenerate
  if (doc.elements.some((el) => el.type === 'graphic' && /^LIST_ICON_/i.test(String(el.slotId || '')))) {
    return { doc: elementsDoc, added: 0 };
  }

  const palette = themeTokens?.palette || {};
  const usedIds = new Set();
  let added = 0;
  const take = Math.min(targets.length, 5);

  for (let i = 0; i < take; i += 1) {
    if (doc.elements.length >= MAX_ELEMENTS_PER_SLIDE) break;
    const textEl = targets[i];
    const pointText = pointTexts[i] || bulletTextAt(content, i);
    if (!String(pointText || '').trim()) continue;

    let graphic = null;
    try {
      graphic = await pickIconForBullet(pointText, themeTokens, usedIds);
    } catch {
      continue;
    }
    if (!graphic?.fileUrl) continue;
    usedIds.add(graphic.id);

    const placement = pickListIconPlacement(textEl, doc.canvas);
    // Nudge title text right when icon sits on the left of a card/col title
    const sid = String(textEl.slotId || '');
    if (/^(CARD|COL|ROW|STEP)_\d+_TITLE$/i.test(sid) || LIST_IMAGE_LABEL_RE.test(sid)) {
      const elIdx = doc.elements.findIndex((e) => e.id === textEl.id || e.slotId === textEl.slotId);
      if (elIdx >= 0 && doc.elements[elIdx]?.placement) {
        const tp = doc.elements[elIdx].placement;
        const shift = LIST_ICON_SIZE + LIST_ICON_GAP;
        doc.elements[elIdx] = {
          ...doc.elements[elIdx],
          placement: {
            ...tp,
            x: Math.round((tp.x || 0) + shift),
            width: Math.max(40, (tp.width || 100) - shift),
          },
        };
      }
    }

    doc.elements.push({
      id: newElementId('graphic'),
      type: 'graphic',
      layer: Math.max(3, (textEl.layer || 10) - 1),
      placement,
      content: {
        assetId: graphic.id,
        src: graphic.fileUrl,
        url: graphic.fileUrl,
        previewUrl: graphic.previewUrl,
        s3Key: graphic.s3Key || undefined,
        colorMode: graphic.colorMode,
        source: graphic.source || 'library',
        colorOverrides:
          graphic.colorMode === 'recolorable'
            ? { primary: palette.primary || palette.accent || true }
            : undefined,
        alt: graphic.name,
        fit: 'contain',
      },
      role: 'list_icon',
      slotId: `LIST_ICON_${slotIndexFromId(textEl.slotId) || i + 1}`,
    });
    added += 1;
  }

  return { doc, added };
}

function injectGraphicsIntoElementsDoc(elementsDoc, graphics = [], { themeTokens } = {}) {
  const doc =
    elementsDoc && typeof elementsDoc === 'object'
      ? {
          version: elementsDoc.version || 1,
          canvas: elementsDoc.canvas || { width: 1920, height: 1080 },
          elements: Array.isArray(elementsDoc.elements) ? [...elementsDoc.elements] : [],
        }
      : { version: 1, canvas: { width: 1920, height: 1080 }, elements: [] };

  const palette = themeTokens?.palette || {};
  const room = MAX_ELEMENTS_PER_SLIDE - doc.elements.length;
  const take = graphics.slice(0, Math.max(0, Math.min(2, room)));
  take.forEach((g, i) => {
    doc.elements.push({
      id: newElementId('graphic'),
      type: 'graphic',
      layer: 2 + i,
      placement: pickCornerPlacement(doc.canvas, i),
      content: {
        assetId: g.id,
        src: g.fileUrl,
        url: g.fileUrl,
        previewUrl: g.previewUrl,
        s3Key: g.s3Key || undefined,
        colorMode: g.colorMode,
        colorOverrides:
          g.colorMode === 'recolorable'
            ? { primary: palette.primary || palette.accent || true }
            : undefined,
        alt: g.name,
      },
      role: 'decoration',
    });
  });
  return doc;
}

async function maybeInjectSlideGraphics(elementsDoc, { content, visualNeed, themeTokens, layoutId } = {}) {
  const lid = String(layoutId || '').toLowerCase();
  const ct = String(
    content?.content_type || content?.contentType || content?.type || ''
  ).toLowerCase();
  const isStructuralSlide =
    ['title', 'closing', 'section_divider', 'agenda', 'quote'].includes(ct) ||
    /^(title_|closing_|section_|quote_|agenda_)/.test(lid) ||
    /title_centered|title_minimal|title_statement|closing_|thank.?you/i.test(lid);

  // Icons only on list/card points — never on hero/closing/section/quote
  if (isStructuralSlide) return elementsDoc;

  // 1) List/card column icons (SVGL brand logos when named; else Graphics Library)
  try {
    const listResult = await injectListIconsIntoElementsDoc(elementsDoc, content || {}, themeTokens);
    if (listResult.added > 0) return listResult.doc;
  } catch {
    /* no corner fallback */
  }

  // Card / multi-column layouts: still try icons when content used atypical keys
  if (/card|para|column|grid|bullet_list|timeline|process|diagram_process/i.test(lid)) {
    try {
      const targets = findListIconTargets(elementsDoc);
      if (targets.length >= 2) {
        const synthetic = {
          ...(content || {}),
          bullets: [],
          columns: targets.map((t, i) => ({
            title: t.content?.text || content?.columns?.[i]?.title || `item ${i + 1}`,
          })),
        };
        const retry = await injectListIconsIntoElementsDoc(elementsDoc, synthetic, themeTokens);
        if (retry.added > 0) return retry.doc;
      }
    } catch {
      /* ignore */
    }
  }

  // No corner decorative accents — icons are list/point only
  return elementsDoc;
}

function tokenizeSlide(content = {}) {
  const colBits = listItemTexts(content);
  const parts = [
    content.title,
    content.heading,
    ...colBits,
    content.body,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  return parts
    .split(/[^a-z0-9]+/i)
    .filter((t) => t.length > 3)
    .slice(0, 12);
}

module.exports = {
  serialize,
  createFromUpload,
  listAdmin,
  getAdmin,
  updateMetadata,
  publish,
  unpublish,
  archive,
  remove,
  listPublished,
  getPublished,
  searchPublished,
  deriveGraphicNeed,
  findListIconTargets,
  injectListIconsIntoElementsDoc,
  maybeInjectSlideGraphics,
};
