const path = require('path');
const crypto = require('crypto');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const s3Service = require('../s3/s3.service');
const stockService = require('../stock/stock.service');
const assetDao = require('../asset/asset.dao');
const presentationDao = require('./presentation.dao');
const { loadPresentationDeck } = require('./deckGeneration.service');
const { blankCanvas, newElementId } = require('./layoutToElements');
const { CANVAS_WIDTH, CANVAS_HEIGHT } = require('./presentation.constants');
const { downloadRemote } = require('../../shared/utils/downloadRemote');
const { attachPresignedMedia } = require('./presignSlideMedia');

const IMAGE_MIME = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);

function assertNotGenerating(deck) {
  if (deck.status === 'GENERATING') {
    throw new AppError(messages.PRESENTATION_ALREADY_GENERATING, 409);
  }
}

function getElementsDoc(slide) {
  if (slide.elements && typeof slide.elements === 'object' && Array.isArray(slide.elements.elements)) {
    return {
      version: slide.elements.version || 1,
      canvas: slide.elements.canvas || { width: CANVAS_WIDTH, height: CANVAS_HEIGHT },
      elements: [...slide.elements.elements],
    };
  }
  return blankCanvas();
}

function applyImageToElements(elementsDoc, { url, s3Key, elementId, assetId, provider }) {
  const doc = {
    version: elementsDoc.version || 1,
    canvas: elementsDoc.canvas || { width: CANVAS_WIDTH, height: CANVAS_HEIGHT },
    elements: Array.isArray(elementsDoc.elements) ? [...elementsDoc.elements] : [],
  };

  let target = null;
  if (elementId) {
    target = doc.elements.find((e) => e.id === elementId && e.type === 'image');
    if (!target) throw new AppError('Image element not found on slide', 404);
  } else {
    target = doc.elements.find((e) => e.type === 'image' && e.role === 'image');
    if (!target) target = doc.elements.find((e) => e.type === 'image');
  }

  const mediaContent = {
    url,
    src: url,
    s3Key,
    fit: 'cover',
  };
  if (assetId) mediaContent.assetId = assetId;
  if (provider) mediaContent.provider = provider;

  if (target) {
    target.content = {
      ...(target.content || {}),
      ...mediaContent,
      fit: target.content?.fit || 'cover',
    };
  } else {
    const canvas = doc.canvas;
    doc.elements.push({
      id: newElementId('img'),
      type: 'image',
      layer: 5,
      placement: {
        x: Math.round(canvas.width * 0.55),
        y: Math.round(canvas.height * 0.1),
        width: Math.round(canvas.width * 0.4),
        height: Math.round(canvas.height * 0.8),
        rotation: 0,
        opacity: 1,
      },
      content: { ...mediaContent, alt: '' },
      role: 'image',
    });
  }

  return doc;
}

async function loadSlideContext(workspaceId, presentationId, slideId) {
  const { deck, project } = await loadPresentationDeck(presentationId, {
    requireWorkspaceId: workspaceId,
  });
  assertNotGenerating(deck);
  const slide = (deck.slides || []).find((s) => s.id === slideId);
  if (!slide) throw new AppError(messages.PRESENTATION_SLIDE_NOT_FOUND, 404);
  return { deck, project, slide };
}

async function persistSlideImage({
  workspaceId,
  presentationId,
  slideId,
  url,
  s3Key,
  source,
  elementId,
  extraImageRef = {},
}) {
  const { deck, slide } = await loadSlideContext(workspaceId, presentationId, slideId);
  const elements = applyImageToElements(getElementsDoc(slide), {
    url,
    s3Key,
    elementId,
    assetId: extraImageRef?.assetId,
    provider: source || extraImageRef?.provider,
  });
  const imageRef = {
    source: source || 'upload',
    url,
    s3Key,
    status: 'ready',
    error: null,
    ...extraImageRef,
  };
  const updated = await presentationDao.updateSlide(slideId, {
    elements,
    imageRef,
    manuallyEdited: true,
    status: 'READY',
  });
  return {
    project: { id: deck.projectId },
    deck: { id: deck.id },
    slide: await attachPresignedMedia(updated),
  };
}

async function uploadSlideMedia({ workspaceId, presentationId, slideId, file, elementId }) {
  if (!file?.buffer) throw new AppError(messages.INVALID_FILE_TYPE, 400);
  if (!IMAGE_MIME.has(file.mimetype)) {
    throw new AppError(messages.INVALID_IMAGE_TYPE, 400);
  }

  const { deck } = await loadSlideContext(workspaceId, presentationId, slideId);
  const ext = path.extname(file.originalname || '') || '.jpg';
  const key = `presentations/${workspaceId}/${deck.id}/images/${slideId}-${crypto.randomUUID()}${ext}`;
  const uploaded = await s3Service.uploadFileToKey(file.buffer, key, file.mimetype);

  return persistSlideImage({
    workspaceId,
    presentationId,
    slideId,
    url: uploaded.url,
    s3Key: uploaded.key,
    source: 'upload',
    elementId: elementId || null,
  });
}

async function attachAsset({ workspaceId, presentationId, slideId, assetId, elementId }) {
  const asset = await assetDao.findAssetById(assetId, workspaceId);
  if (!asset) throw new AppError(messages.ASSET_NOT_FOUND || 'Asset not found', 404);

  let url = asset.url;
  if (asset.key) {
    try {
      url = await s3Service.getPresignedGetUrl(asset.key, 3600);
    } catch {
      url = asset.url || s3Service.buildPublicUrl(asset.key);
    }
  }

  return persistSlideImage({
    workspaceId,
    presentationId,
    slideId,
    url,
    s3Key: asset.key || null,
    source: 'asset',
    elementId: elementId || null,
    extraImageRef: { assetId: asset.id },
  });
}

async function insertStock({
  workspaceId,
  presentationId,
  slideId,
  query,
  provider,
  externalId,
  elementId,
  userId,
}) {
  const { deck } = await loadSlideContext(workspaceId, presentationId, slideId);

  let buffer;
  let contentType = 'image/jpeg';
  let meta = {};

  if (provider && externalId) {
    const workspace = { id: workspaceId };
    const asset = await stockService.importStockAsset({
      userId,
      workspace,
      provider,
      externalId,
      mediaType: 'photo',
    });
    return persistSlideImage({
      workspaceId,
      presentationId,
      slideId,
      url: asset.url,
      s3Key: asset.key,
      source: 'stock',
      elementId: elementId || null,
      extraImageRef: {
        assetId: asset.id,
        provider,
        externalId: String(externalId),
      },
    });
  }

  const q = String(query || '').trim();
  if (!q) throw new AppError('query or provider+externalId is required', 400);

  const result = await stockService.searchStock({
    q,
    type: 'photo',
    page: 1,
    perPage: 5,
    provider: 'all',
  });
  const item = result?.items?.[0];
  if (!item) throw new AppError('No stock images found for query', 404);

  const downloadUrl = item.previewUrl || item.downloadUrl || item.url;
  if (!downloadUrl) throw new AppError('Stock item missing download URL', 502);

  buffer = await downloadRemote(downloadUrl, { maxBytes: 8 * 1024 * 1024 });
  meta = {
    provider: item.provider || null,
    externalId: item.externalId || item.id || null,
    attribution: item.attribution || null,
  };

  const key = `presentations/${workspaceId}/${deck.id}/images/${slideId}-${crypto.randomUUID()}.jpg`;
  const uploaded = await s3Service.uploadFileToKey(buffer, key, contentType);

  return persistSlideImage({
    workspaceId,
    presentationId,
    slideId,
    url: uploaded.url,
    s3Key: uploaded.key,
    source: 'stock',
    elementId: elementId || null,
    extraImageRef: meta,
  });
}

module.exports = {
  uploadSlideMedia,
  attachAsset,
  insertStock,
};
