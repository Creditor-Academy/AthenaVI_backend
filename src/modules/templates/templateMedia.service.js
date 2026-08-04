const path = require('path');
const { randomUUID } = require('crypto');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const s3Service = require('../s3/s3.service');
const templateMediaDao = require('./templateMedia.dao');
const prisma = require('../../shared/config/prismaClient');

const IMAGE_MIME = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);
const MEDIA_KINDS = new Set(['photo', 'preview', 'graphic']);

function systemMediaKey(templateId, slotHint, originalName = 'image.jpg') {
  const ext = path.extname(originalName) || '.jpg';
  const safeSlot = String(slotHint || 'photo')
    .replace(/[^a-zA-Z0-9:_-]/g, '_')
    .slice(0, 64);
  return `presentations/_system/templates/${templateId}/${safeSlot}-${randomUUID()}${ext}`;
}

function packSlideMediaKey(packId, order, ext = '.jpg') {
  return `presentations/_system/packs/${packId}/slide-${order}${ext}`;
}

async function resolveMediaUrl(s3Key) {
  if (!s3Key) return null;
  try {
    return await s3Service.getPresignedGetUrl(s3Key, 3600);
  } catch {
    return s3Service.buildPublicUrl(s3Key);
  }
}

async function attachUrls(mediaRows) {
  return Promise.all(
    (mediaRows || []).map(async (m) => ({
      ...m,
      url: await resolveMediaUrl(m.s3Key),
    }))
  );
}

function layoutHasImageSlot(layoutSchema) {
  const slots = Array.isArray(layoutSchema?.slots) ? layoutSchema.slots : [];
  return slots.some((slot) => {
    const id = String(slot.id || '').toLowerCase();
    const role = String(slot.role || '').toLowerCase();
    return (
      role === 'image' ||
      id.includes('image') ||
      id === 'hero' ||
      slot.fit === 'cover'
    );
  });
}

function slotHintForSlideOrder(order) {
  return `slide:${Number(order) || 1}`;
}

async function getTemplateOrThrow(templateId) {
  const template = await prisma.template.findUnique({ where: { id: templateId } });
  if (!template) throw new AppError(messages.TEMPLATE_NOT_FOUND, 404);
  return template;
}

async function listMedia(templateId) {
  await getTemplateOrThrow(templateId);
  const rows = await templateMediaDao.listByTemplateId(templateId);
  return attachUrls(rows);
}

async function uploadMedia({ templateId, file, kind, slotHint, name, setAsPreview }) {
  await getTemplateOrThrow(templateId);
  if (!file?.buffer) throw new AppError(messages.INVALID_FILE_TYPE, 400);
  if (!IMAGE_MIME.has(file.mimetype)) {
    throw new AppError(messages.INVALID_IMAGE_TYPE, 400);
  }

  const mediaKind = String(kind || 'photo').toLowerCase();
  if (!MEDIA_KINDS.has(mediaKind)) {
    throw new AppError('kind must be photo, preview, or graphic', 400);
  }

  let hint =
    slotHint != null && String(slotHint).trim()
      ? String(slotHint).trim().slice(0, 128)
      : null;

  // Default slot so uploads are discoverable (not a random photo:uuid that never maps to preview)
  if (!hint) {
    if (mediaKind === 'preview') hint = 'preview';
    else if (mediaKind === 'graphic') hint = `graphic:${randomUUID().slice(0, 8)}`;
    else hint = 'slide:1';
  }

  const key = systemMediaKey(templateId, hint, file.originalname || 'image.jpg');
  const uploaded = await s3Service.uploadFileToKey(file.buffer, key, file.mimetype);
  const sortOrder = (await templateMediaDao.maxSortOrder(templateId, mediaKind)) + 1;

  const existing = await templateMediaDao.findBySlotHint(templateId, hint);
  if (existing?.s3Key && existing.s3Key !== uploaded.key) {
    try {
      await s3Service.deleteFile(existing.s3Key);
    } catch {
      // best-effort
    }
  }

  const media = await templateMediaDao.upsertBySlotHint({
    templateId,
    kind: mediaKind === 'preview' ? 'preview' : mediaKind,
    slotHint: hint,
    name: name || file.originalname || null,
    s3Key: uploaded.key,
    mimeType: file.mimetype,
    sortOrder: existing ? existing.sortOrder : sortOrder,
  });

  // Pack picker uses kind/slotHint "preview". Sync so uploads actually show in preview.
  const existingPreview = await templateMediaDao.findBySlotHint(templateId, 'preview');
  const explicitlyOff = setAsPreview === false || setAsPreview === 'false';
  const explicitlyOn = setAsPreview === true || setAsPreview === 'true';
  const looksLikeHero =
    mediaKind === 'preview' || hint === 'preview' || String(hint).startsWith('slide:1');
  const shouldSyncPreview =
    !explicitlyOff && (explicitlyOn || looksLikeHero || !existingPreview);

  if (shouldSyncPreview && hint !== 'preview') {
    if (existingPreview?.s3Key && existingPreview.s3Key !== uploaded.key) {
      // Keep old preview object if it was a dedicated key unused elsewhere — best-effort skip delete
    }
    await templateMediaDao.upsertBySlotHint({
      templateId,
      kind: 'preview',
      slotHint: 'preview',
      name: name || file.originalname || 'preview',
      s3Key: uploaded.key,
      mimeType: file.mimetype,
      sortOrder: 0,
    });
  }

  return { ...media, url: await resolveMediaUrl(media.s3Key) };
}

async function deleteMedia({ templateId, mediaId }) {
  await getTemplateOrThrow(templateId);
  const media = await templateMediaDao.findById(templateId, mediaId);
  if (!media) throw new AppError(messages.TEMPLATE_MEDIA_NOT_FOUND, 404);
  await templateMediaDao.deleteMedia(mediaId);
  try {
    await s3Service.deleteFile(media.s3Key);
  } catch {
    // best-effort
  }
  return { id: mediaId, deleted: true };
}

async function withMediaAttached(template) {
  if (!template) return template;
  const media = await attachUrls(await templateMediaDao.listByTemplateId(template.id));
  return { ...template, media };
}

async function withMediaAttachedMany(templates) {
  if (!templates?.length) return templates || [];
  const ids = templates.map((t) => t.id);
  const allMedia = await templateMediaDao.listMediaForTemplates(ids);
  const byTemplate = new Map();
  for (const m of allMedia) {
    if (!byTemplate.has(m.templateId)) byTemplate.set(m.templateId, []);
    byTemplate.get(m.templateId).push(m);
  }
  return Promise.all(
    templates.map(async (t) => ({
      ...t,
      media: await attachUrls(byTemplate.get(t.id) || []),
    }))
  );
}

/**
 * Copy an existing S3 object into a template media slot (system key).
 */
async function copyKeyToTemplateSlot({
  templateId,
  sourceKey,
  kind = 'photo',
  slotHint,
  name = null,
  mimeType = 'image/jpeg',
  destKey = null,
  setAsPreview = false,
}) {
  if (!sourceKey || !templateId || !slotHint) return null;
  await getTemplateOrThrow(templateId);

  const mediaKind = String(kind || 'photo').toLowerCase();
  if (!MEDIA_KINDS.has(mediaKind)) {
    throw new AppError('kind must be photo, preview, or graphic', 400);
  }

  const hint = String(slotHint).trim().slice(0, 128);
  const key =
    destKey ||
    systemMediaKey(templateId, hint, path.basename(sourceKey) || 'image.jpg');

  if (sourceKey !== key) {
    await s3Service.copyFile(sourceKey, key);
  }

  const existing = await templateMediaDao.findBySlotHint(templateId, hint);
  const sortOrder = existing
    ? existing.sortOrder
    : (await templateMediaDao.maxSortOrder(templateId, mediaKind)) + 1;

  const media = await templateMediaDao.upsertBySlotHint({
    templateId,
    kind: mediaKind === 'preview' ? 'preview' : mediaKind,
    slotHint: hint,
    name: name || null,
    s3Key: key,
    mimeType: mimeType || 'image/jpeg',
    sortOrder,
  });

  if (setAsPreview && hint !== 'preview') {
    await templateMediaDao.upsertBySlotHint({
      templateId,
      kind: 'preview',
      slotHint: 'preview',
      name: name || 'preview',
      s3Key: key,
      mimeType: mimeType || 'image/jpeg',
      sortOrder: 0,
    });
  }

  return {
    ...media,
    url: await resolveMediaUrl(media.s3Key),
  };
}

async function resolvePackSlideImageRef({ packTemplateId, slideOrder, placeholder, mediaByHint }) {
  // Resolve imageRef for a pack slide from TemplateMedia / placeholder.imageS3Key.
  const hint = slotHintForSlideOrder(slideOrder);
  let s3Key =
    (placeholder && typeof placeholder.imageS3Key === 'string' && placeholder.imageS3Key.trim()) ||
    null;
  let mediaId = null;
  let source = 'template';

  if (!s3Key && mediaByHint) {
    const row = mediaByHint.get(hint) || mediaByHint.get('image') || null;
    if (row?.s3Key) {
      s3Key = row.s3Key;
      mediaId = row.id;
    }
  }

  if (!s3Key && packTemplateId) {
    const row =
      (await templateMediaDao.findBySlotHint(packTemplateId, hint)) ||
      (await templateMediaDao.findBySlotHint(packTemplateId, 'image'));
    if (row?.s3Key) {
      s3Key = row.s3Key;
      mediaId = row.id;
    }
  }

  if (!s3Key) return null;

  const url = await resolveMediaUrl(s3Key);
  return {
    source,
    url,
    s3Key,
    mediaId,
    status: 'ready',
    error: null,
  };
}

module.exports = {
  IMAGE_MIME,
  MEDIA_KINDS,
  systemMediaKey,
  packSlideMediaKey,
  resolveMediaUrl,
  attachUrls,
  layoutHasImageSlot,
  slotHintForSlideOrder,
  listMedia,
  uploadMedia,
  deleteMedia,
  withMediaAttached,
  withMediaAttachedMany,
  resolvePackSlideImageRef,
  copyKeyToTemplateSlot,
  getTemplateOrThrow,
};
