const path = require('path');
const { randomUUID } = require('crypto');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const prisma = require('../../shared/config/prismaClient');
const s3Service = require('../s3/s3.service');
const templateAdminService = require('./templateAdmin.service');
const templateMediaService = require('./templateMedia.service');
const presentationDao = require('../presentation/presentation.dao');

const AI_TEXT_ROLES = new Set([
  'title',
  'heading',
  'headline',
  'subtitle',
  'subheading',
  'body',
  'bullets',
  'caption',
  'quote',
  'cta',
  'stat_value',
  'stat_label',
  'lead',
  'attribution',
]);

function deepClone(value) {
  return JSON.parse(JSON.stringify(value ?? null));
}

function guessMimeFromKey(key) {
  const ext = String(path.extname(key || '') || '').toLowerCase();
  if (ext === '.png') return 'image/png';
  if (ext === '.webp') return 'image/webp';
  if (ext === '.gif') return 'image/gif';
  if (ext === '.mp4') return 'video/mp4';
  if (ext === '.webm') return 'video/webm';
  if (ext === '.mp3') return 'audio/mpeg';
  if (ext === '.wav') return 'audio/wav';
  return 'image/jpeg';
}

function extractSlideImageKey(slide) {
  if (slide?.imageRef?.s3Key) return slide.imageRef.s3Key;
  if (slide?.content?.imageS3Key) return slide.content.imageS3Key;
  const elements = Array.isArray(slide?.elements?.elements) ? slide.elements.elements : [];
  for (const el of elements) {
    if (el?.type === 'image' && el.role !== 'logo' && el?.content?.s3Key) {
      return el.content.s3Key;
    }
  }
  return null;
}

function slideIsAiReady(slideEntry) {
  if (slideEntry.layout_id && String(slideEntry.layout_id).trim()) return true;
  const els = slideEntry.snapshot?.elements?.elements;
  if (!Array.isArray(els) || !els.length) return false;
  const hasTextRole = els.some((el) => {
    const role = String(el.role || '').toLowerCase();
    return AI_TEXT_ROLES.has(role);
  });
  const imageEls = els.filter((el) => el.type === 'image' && el.role !== 'logo');
  const imageOk =
    imageEls.length === 0 || imageEls.some((el) => String(el.role || '').toLowerCase() === 'image');
  return hasTextRole && imageOk;
}

function rewriteKeysInValue(value, keyMap) {
  if (value == null) return value;
  if (typeof value === 'string') {
    const mapped = keyMap.get(value);
    return mapped?.s3Key || value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => rewriteKeysInValue(item, keyMap));
  }
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if ((k === 's3Key' || k === 'key') && typeof v === 'string' && keyMap.has(v)) {
        out[k] = keyMap.get(v).s3Key;
        if (keyMap.get(v).url && (out.url == null || k === 's3Key')) {
          out.url = keyMap.get(v).url;
        }
      } else if (k === 'url' && typeof v === 'string') {
        // leave urls; refreshed via s3Key when present
        out[k] = v;
      } else {
        out[k] = rewriteKeysInValue(v, keyMap);
      }
    }
    return out;
  }
  return value;
}

function collectS3KeysFromValue(value, out = new Set()) {
  if (value == null) return out;
  if (Array.isArray(value)) {
    for (const item of value) collectS3KeysFromValue(item, out);
    return out;
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if ((k === 's3Key' || k === 'key') && typeof v === 'string' && v.trim()) {
        out.add(v.trim());
      } else {
        collectS3KeysFromValue(v, out);
      }
    }
  }
  return out;
}

async function copyKeysToSystemPrefix(keys, destPrefix) {
  const keyMap = new Map();
  for (const sourceKey of keys) {
    if (!sourceKey || keyMap.has(sourceKey)) continue;
    const ext = path.extname(sourceKey) || '.bin';
    const destKey = `${destPrefix}/${randomUUID()}${ext}`;
    try {
      const copied = await s3Service.copyFile(sourceKey, destKey);
      keyMap.set(sourceKey, {
        s3Key: copied.key,
        url: copied.url || s3Service.buildPublicUrl(copied.key),
      });
    } catch (err) {
      // Skip missing/unreadable sources; keep original key in snapshot
    }
  }
  return keyMap;
}

async function assertPackIdUnique(type, packId) {
  const existing = await prisma.template.findFirst({
    where: {
      type,
      schema: { path: ['pack_id'], equals: packId },
    },
    select: { id: true },
  });
  if (existing) {
    throw new AppError(`pack_id already exists: ${packId}`, 409);
  }
}

function buildPlaceholderFromContent(content = {}) {
  if (!content || typeof content !== 'object') return {};
  const {
    intent,
    designTokens,
    generationHints,
    visual_need,
    content_type,
    ...rest
  } = content;
  return rest;
}

async function loadPresentationForPublish(presentationId) {
  const deck = await presentationDao.findDeckByProjectId(presentationId);
  if (!deck) {
    throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
  }
  const project = await prisma.project.findUnique({
    where: { id: presentationId },
    select: {
      id: true,
      name: true,
      workspaceId: true,
      type: true,
      folderId: true,
    },
  });
  if (!project || project.type !== 'PRESENTATION') {
    throw new AppError(messages.PRESENTATION_NOT_FOUND, 404);
  }
  return { deck, project };
}

/**
 * Publish a presentation canvas as a hybrid DECK_PACK.
 */
async function publishPresentationAsPack({
  presentationId,
  userId,
  name,
  packId,
  themeId,
  isActive = true,
  variant = 'canvas',
  contentType = null,
  description = null,
}) {
  const { deck, project } = await loadPresentationForPublish(presentationId);
  const slides = Array.isArray(deck.slides) ? [...deck.slides].sort((a, b) => a.order - b.order) : [];
  if (!slides.length) {
    throw new AppError('Presentation has no slides to publish', 400);
  }

  const normalizedPackId = String(packId).trim();
  await assertPackIdUnique('DECK_PACK', normalizedPackId);

  const packSlides = slides.map((slide) => {
    const content = slide.content && typeof slide.content === 'object' ? slide.content : {};
    const elementsDoc =
      slide.elements && typeof slide.elements === 'object'
        ? deepClone(slide.elements)
        : { version: 1, canvas: {}, elements: [] };
    const layoutId = slide.layoutId || content.layout_id || null;
    const entry = {
      order: slide.order,
      contentType: slide.contentType || content.content_type || 'title_body',
      intent: content.intent || null,
      designTokens: content.designTokens || null,
      generationHints: content.generationHints || null,
      placeholder: buildPlaceholderFromContent(content),
      snapshot: {
        elements: elementsDoc,
        imageS3Key: extractSlideImageKey(slide) || null,
      },
    };
    if (layoutId) entry.layout_id = layoutId;
    return entry;
  });

  const aiReady = packSlides.every(slideIsAiReady);
  const schema = {
    schemaVersion: 1,
    pack_id: normalizedPackId,
    themeId: themeId || deck.themeTokens?.themeId || null,
    aspectRatio: deck.aspectRatio || '16:9',
    meta: {
      name,
      description: description || null,
      authoredVia: 'canvas',
      aiReady,
      sourcePresentationId: presentationId,
      sourceWorkspaceId: project.workspaceId,
    },
    slides: packSlides,
    preview: {
      label: name,
      slideCount: packSlides.length,
    },
  };

  const template = await templateAdminService.createTemplate({
    name,
    contentType: contentType || null,
    variant: variant || 'canvas',
    schema,
    type: 'DECK_PACK',
    isActive,
    createdBy: userId,
  });

  // Copy slide images into TemplateMedia and rewrite snapshot keys
  const updatedSlides = [];
  for (const ps of packSlides) {
    const sourceKey = ps.snapshot?.imageS3Key || null;
    let next = deepClone(ps);
    if (sourceKey) {
      const hint = templateMediaService.slotHintForSlideOrder(ps.order);
      const destKey = templateMediaService.packSlideMediaKey(
        normalizedPackId,
        ps.order,
        path.extname(sourceKey) || '.jpg'
      );
      try {
        const media = await templateMediaService.copyKeyToTemplateSlot({
          templateId: template.id,
          sourceKey,
          kind: 'photo',
          slotHint: hint,
          name: `slide-${ps.order}`,
          mimeType: guessMimeFromKey(sourceKey),
          destKey,
          setAsPreview: ps.order === 1,
        });
        if (media?.s3Key) {
          next.snapshot.imageS3Key = media.s3Key;
          if (next.placeholder && typeof next.placeholder === 'object') {
            next.placeholder.imageS3Key = media.s3Key;
          }
          const keyMap = new Map([[sourceKey, { s3Key: media.s3Key, url: media.url }]]);
          next.snapshot.elements = rewriteKeysInValue(next.snapshot.elements, keyMap);
        }
      } catch {
        // keep original keys if copy fails
      }
    }
    updatedSlides.push(next);
  }

  const finalSchema = {
    ...schema,
    slides: updatedSlides,
    meta: { ...schema.meta, aiReady },
  };

  return templateAdminService.updateTemplate({
    id: template.id,
    schema: finalSchema,
  });
}

function stripSceneForBlueprint(scene) {
  const cloned = deepClone(scene) || {};
  delete cloned.sceneId;
  delete cloned.templateId;
  return {
    name: cloned.name || 'Scene',
    order: cloned.order != null ? cloned.order : 0,
    durationInFrames: cloned.durationInFrames,
    locked: cloned.locked === true,
    layout: cloned.layout || undefined,
    background: cloned.background,
    elements: Array.isArray(cloned.elements) ? cloned.elements : [],
    ...(cloned.presenter ? { presenter: cloned.presenter } : {}),
    ...(cloned.transition ? { transition: cloned.transition } : {}),
  };
}

async function loadVideoProject(projectId) {
  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: {
      id: true,
      name: true,
      workspaceId: true,
      type: true,
      data: true,
      folderId: true,
    },
  });
  if (!project || project.type === 'PRESENTATION') {
    throw new AppError(messages.PROJECT_NOT_FOUND, 404);
  }
  return project;
}

/**
 * Publish one project scene as VIDEO_SCENE.
 */
async function publishProjectSceneAsTemplate({
  projectId,
  sceneId,
  userId,
  name,
  contentType = null,
  variant = 'canvas',
  isActive = true,
}) {
  const project = await loadVideoProject(projectId);
  const data = project.data && typeof project.data === 'object' ? project.data : {};
  const scenes = Array.isArray(data.scenes) ? data.scenes : [];
  const scene = scenes.find((s) => String(s.sceneId) === String(sceneId));
  if (!scene) {
    throw new AppError('Scene not found on project', 404);
  }

  const keys = collectS3KeysFromValue(scene);
  const destPrefix = `videos/_system/templates/pending`;
  const keyMap = await copyKeysToSystemPrefix([...keys], destPrefix);
  const rewritten = rewriteKeysInValue(stripSceneForBlueprint(scene), keyMap);

  const schema = {
    version: 1,
    videoSettings: data.videoSettings || undefined,
    meta: {
      authoredVia: 'canvas',
      name,
      sourceProjectId: projectId,
      sourceSceneId: sceneId,
    },
    scene: rewritten,
  };

  const template = await templateAdminService.createTemplate({
    name,
    contentType: contentType || null,
    variant: variant || 'canvas',
    schema,
    type: 'VIDEO_SCENE',
    isActive,
    createdBy: userId,
  });

  // Move copied keys under final template id prefix when possible
  if (keyMap.size) {
    const finalMap = new Map();
    for (const [src, info] of keyMap.entries()) {
      const ext = path.extname(info.s3Key) || '.bin';
      const finalKey = `videos/_system/templates/${template.id}/${randomUUID()}${ext}`;
      try {
        await s3Service.copyFile(info.s3Key, finalKey);
        try {
          await s3Service.deleteFile(info.s3Key);
        } catch {
          // best-effort
        }
        finalMap.set(info.s3Key, {
          s3Key: finalKey,
          url: s3Service.buildPublicUrl(finalKey),
        });
      } catch {
        finalMap.set(info.s3Key, info);
      }
    }
    const finalScene = rewriteKeysInValue(schema.scene, finalMap);
    return templateAdminService.updateTemplate({
      id: template.id,
      schema: { ...schema, scene: finalScene },
    });
  }

  return templateMediaService.withMediaAttached(template);
}

/**
 * Publish entire video project as VIDEO_PACK (all scenes).
 */
async function publishProjectAsVideoPack({
  projectId,
  userId,
  name,
  packId,
  isActive = true,
  variant = 'canvas',
  contentType = null,
  description = null,
}) {
  const project = await loadVideoProject(projectId);
  const data = project.data && typeof project.data === 'object' ? project.data : {};
  const scenes = Array.isArray(data.scenes) ? [...data.scenes] : [];
  if (!scenes.length) {
    throw new AppError('Project has no scenes to publish', 400);
  }

  const normalizedPackId = String(packId).trim();
  await assertPackIdUnique('VIDEO_PACK', normalizedPackId);

  scenes.sort((a, b) => (Number(a.order) || 0) - (Number(b.order) || 0));

  const keys = collectS3KeysFromValue({ scenes, videoSettings: data.videoSettings });
  const destPrefix = `videos/_system/packs/${normalizedPackId}`;
  const keyMap = await copyKeysToSystemPrefix([...keys], destPrefix);
  const rewrittenScenes = rewriteKeysInValue(deepClone(scenes), keyMap).map((s, idx) => ({
    ...s,
    order: s.order != null ? s.order : idx,
  }));

  const schema = {
    schemaVersion: 1,
    pack_id: normalizedPackId,
    meta: {
      authoredVia: 'canvas',
      name,
      description: description || null,
      sourceProjectId: projectId,
      sourceWorkspaceId: project.workspaceId,
    },
    videoSettings: data.videoSettings || undefined,
    scenes: rewrittenScenes,
    preview: {
      label: name,
      sceneCount: rewrittenScenes.length,
    },
  };

  return templateAdminService.createTemplate({
    name,
    contentType: contentType || null,
    variant: variant || 'canvas',
    schema,
    type: 'VIDEO_PACK',
    isActive,
    createdBy: userId,
  });
}

module.exports = {
  publishPresentationAsPack,
  publishProjectSceneAsTemplate,
  publishProjectAsVideoPack,
  AI_TEXT_ROLES,
  slideIsAiReady,
};
