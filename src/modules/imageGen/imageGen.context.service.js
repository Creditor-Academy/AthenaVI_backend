const { v4: uuidv4 } = require('uuid');
const path = require('path');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const { moderateText } = require('../../shared/services/ai/moderation.service');
const { uploadFileToKey, getObjectBuffer, deleteFile } = require('../s3/s3.service');
const assetDao = require('../asset/asset.dao');
const contextDao = require('./imageGen.context.dao');
const contextRateLimit = require('./imageGen.contextRateLimit.service');
const contextParse = require('./imageGen.contextParse.service');
const {
  buildEnrichmentBlock,
  appendContextBlock,
  withReferenceImageIndexHints,
} = require('./prompts/contextEnrichment.prompt');

const MAX_FILES =
  Number(process.env.IMAGE_GEN_CONTEXT_MAX_FILES) > 0
    ? Number(process.env.IMAGE_GEN_CONTEXT_MAX_FILES)
    : 5;

const TTL_DAYS =
  Number(process.env.IMAGE_GEN_CONTEXT_TTL_DAYS) > 0
    ? Number(process.env.IMAGE_GEN_CONTEXT_TTL_DAYS)
    : 7;

function getWorkspaceMemberRole(workspace, userId) {
  if (!workspace || !Array.isArray(workspace.members)) return null;
  const member = workspace.members.find((item) => item.userId === userId);
  return member ? member.role : null;
}

function serializeContext(row) {
  if (!row) return row;
  const derived = row.derived && typeof row.derived === 'object' ? row.derived : {};
  return {
    id: row.id,
    status: row.status,
    expiresAt: row.expiresAt,
    pinnedAt: row.pinnedAt || null,
    createdAt: row.createdAt,
    previews: derived.previews || {
      inlineText: row.inlineText || null,
      documents: [],
      images: [],
      assetRefs: [],
    },
    warnings: Array.isArray(derived.warnings) ? derived.warnings : [],
  };
}

function assertContextAccessible(row, workspace, userId) {
  if (!row) {
    throw new AppError(messages.IMAGE_GEN_CONTEXT_NOT_FOUND, 404);
  }
  if (workspace.type === 'PRIVATE' && row.userId !== userId) {
    throw new AppError(messages.IMAGE_GEN_CONTEXT_NOT_FOUND, 404);
  }
}

function isContextUsable(row) {
  if (!row) return false;
  if (row.pinnedAt) return true;
  return new Date(row.expiresAt).getTime() > Date.now();
}

async function createContext({ userId, workspace, files = [], body = {} }) {
  await contextRateLimit.assertContextCreateAllowed(userId, workspace.id);

  const inlineText =
    body.inlineText != null && String(body.inlineText).trim()
      ? String(body.inlineText).trim()
      : '';
  const assetIds = Array.isArray(body.assetIds)
    ? [...new Set(body.assetIds.filter(Boolean).map(String))]
    : [];
  const uploads = Array.isArray(files) ? files : [];

  if (!uploads.length && !assetIds.length && !inlineText) {
    throw new AppError(messages.IMAGE_GEN_CONTEXT_EMPTY, 400);
  }

  if (uploads.length + assetIds.length > MAX_FILES) {
    throw new AppError(messages.IMAGE_GEN_CONTEXT_TOO_MANY_FILES, 400);
  }

  const contextId = uuidv4();
  const warnings = [];
  const parsedEntries = [];

  // Resolve workspace assets (images only)
  for (const assetId of assetIds) {
    // eslint-disable-next-line no-await-in-loop
    const asset = await assetDao.findAssetById(assetId, workspace.id);
    if (!asset) {
      throw new AppError(messages.IMAGE_GEN_CONTEXT_ASSET_NOT_FOUND, 400);
    }
    const mime = String(asset.type || '').toLowerCase();
    if (!mime.startsWith('image/')) {
      throw new AppError(messages.IMAGE_GEN_CONTEXT_ASSET_NOT_IMAGE, 400);
    }
    // eslint-disable-next-line no-await-in-loop
    const buffer = await getObjectBuffer(asset.key);
    // eslint-disable-next-line no-await-in-loop
    const parsed = await contextParse.parseContextFile(
      {
        buffer,
        originalname: asset.name || 'asset.png',
        mimetype: mime,
      },
      { hint: inlineText }
    );
    parsedEntries.push({
      source: 'asset',
      assetId: asset.id,
      name: parsed.name,
      mimeType: parsed.mimeType,
      s3Key: asset.key,
      role: parsed.role,
      extractedText: parsed.extractedText,
      imageSummary: parsed.imageSummary,
      truncated: parsed.truncated,
      excerpt: parsed.excerpt,
    });
  }

  // Upload + parse multipart files
  for (const file of uploads) {
    const parsed = await contextParse.parseContextFile(file, { hint: inlineText });
    const ext = path.extname(parsed.name) || '';
    const key = `workspace/${workspace.id}/image-gen-context/${contextId}/${uuidv4()}${ext}`;
    // eslint-disable-next-line no-await-in-loop
    await uploadFileToKey(file.buffer, key, parsed.mimeType);
    parsedEntries.push({
      source: 'upload',
      assetId: null,
      name: parsed.name,
      mimeType: parsed.mimeType,
      s3Key: key,
      role: parsed.role,
      extractedText: parsed.extractedText,
      imageSummary: parsed.imageSummary,
      truncated: parsed.truncated,
      excerpt: parsed.excerpt,
    });
  }

  const documents = parsedEntries
    .filter((e) => e.role === 'document')
    .map((e) => ({
      name: e.name,
      excerpt: e.excerpt || contextParse.excerpt(e.extractedText),
      truncated: Boolean(e.truncated),
      text: e.extractedText,
    }));

  const images = parsedEntries
    .filter((e) => e.role === 'reference_image')
    .map((e) => ({
      name: e.name,
      summary: e.imageSummary,
    }));

  const assetRefs = parsedEntries
    .filter((e) => e.source === 'asset')
    .map((e) => ({
      assetId: e.assetId,
      name: e.name,
      role: e.role,
    }));

  if (documents.some((d) => d.truncated)) {
    warnings.push('One or more documents were truncated to the max character limit.');
  }

  const moderationText = [inlineText, ...documents.map((d) => d.text || '')]
    .filter(Boolean)
    .join('\n\n');
  if (moderationText.trim()) {
    await moderateText(moderationText);
  }

  const enrichmentBlock = buildEnrichmentBlock({
    inlineText,
    documents,
    images,
  });

  const derived = {
    previews: {
      inlineText: inlineText || null,
      documents: documents.map(({ name, excerpt, truncated }) => ({
        name,
        excerpt,
        truncated,
      })),
      images,
      assetRefs,
    },
    warnings,
    enrichmentBlock,
  };

  const expiresAt = new Date(Date.now() + TTL_DAYS * 24 * 60 * 60 * 1000);

  const row = await contextDao.createContextWithFiles({
    context: {
      id: contextId,
      workspaceId: workspace.id,
      userId,
      status: 'READY',
      inlineText: inlineText || null,
      derived,
      expiresAt,
      pinnedAt: null,
    },
    files: parsedEntries.map((e) => ({
      source: e.source,
      assetId: e.assetId,
      name: e.name,
      mimeType: e.mimeType,
      s3Key: e.s3Key,
      role: e.role,
      extractedText: e.extractedText || null,
      imageSummary: e.imageSummary || null,
    })),
  });

  return serializeContext(row);
}

async function getContext({ userId, workspace, contextId }) {
  const row = await contextDao.findById(contextId, workspace.id, {
    userId,
    isPrivate: workspace.type === 'PRIVATE',
  });
  assertContextAccessible(row, workspace, userId);
  if (!isContextUsable(row)) {
    throw new AppError(messages.IMAGE_GEN_CONTEXT_EXPIRED, 404);
  }
  return serializeContext(row);
}

async function deleteContext({ userId, workspace, contextId }) {
  const row = await contextDao.findById(contextId, workspace.id, {
    userId,
    isPrivate: workspace.type === 'PRIVATE',
  });
  assertContextAccessible(row, workspace, userId);

  if (row.pinnedAt) {
    throw new AppError(messages.IMAGE_GEN_CONTEXT_PINNED, 409);
  }

  const isCreator = row.userId === userId;
  if (!isCreator) {
    if (workspace.type === 'PRIVATE') {
      throw new AppError(messages.IMAGE_GEN_CONTEXT_NOT_FOUND, 404);
    }
    const role = getWorkspaceMemberRole(workspace, userId);
    if (role !== 'OWNER' && role !== 'ADMIN') {
      throw new AppError(messages.IMAGE_GEN_CONTEXT_NOT_FOUND, 404);
    }
  }

  for (const file of row.files || []) {
    if (file.source === 'upload' && file.s3Key) {
      try {
        // eslint-disable-next-line no-await-in-loop
        await deleteFile(file.s3Key);
      } catch {
        // continue deleting remaining keys
      }
    }
  }

  await contextDao.deleteContext(row.id);
  return { deleted: true };
}

async function loadReferenceBuffers(files = []) {
  const imageFiles = files.filter((f) => f.role === 'reference_image' && f.s3Key);
  const buffers = [];
  for (const file of imageFiles) {
    // eslint-disable-next-line no-await-in-loop
    const buffer = await getObjectBuffer(file.s3Key);
    buffers.push(buffer);
  }
  return buffers;
}

/**
 * Resolve context for generate/regenerate.
 * Returns enrichment + optional reference image buffers.
 * When live context is unusable and parentSnapshot is provided, falls back to text-only snapshot.
 */
async function resolveForGenerate({
  contextId,
  workspace,
  userId,
  parentSnapshot = null,
  requireLive = false,
} = {}) {
  const empty = {
    contextId: null,
    enrichmentBlock: '',
    referenceImageBuffers: [],
    contextPreview: null,
    contextSnapshot: null,
    usedLiveContext: false,
    pinContextId: null,
  };

  if (contextId) {
    const row = await contextDao.findById(contextId, workspace.id, {
      userId,
      isPrivate: workspace.type === 'PRIVATE',
    });

    if (row) {
      assertContextAccessible(row, workspace, userId);
      if (isContextUsable(row)) {
        const derived = row.derived && typeof row.derived === 'object' ? row.derived : {};
        const enrichmentBlock = String(derived.enrichmentBlock || '').trim();
        const referenceImageBuffers = await loadReferenceBuffers(row.files || []);
        const previews = derived.previews || {};
        const contextPreview = {
          documentCount: Array.isArray(previews.documents) ? previews.documents.length : 0,
          imageCount: Array.isArray(previews.images) ? previews.images.length : 0,
        };
        const contextSnapshot = {
          enrichmentBlock,
          referenceImageCount: referenceImageBuffers.length,
          previews,
        };

        return {
          contextId: row.id,
          enrichmentBlock,
          referenceImageBuffers,
          contextPreview,
          contextSnapshot,
          usedLiveContext: true,
          pinContextId: row.id,
        };
      }
    }

    // Explicit generate with bad/expired contextId — hard fail
    if (requireLive || !parentSnapshot) {
      if (!row) {
        throw new AppError(messages.IMAGE_GEN_CONTEXT_NOT_FOUND, 404);
      }
      throw new AppError(messages.IMAGE_GEN_CONTEXT_EXPIRED, 400);
    }
    // else fall through to snapshot
  }

  if (parentSnapshot && typeof parentSnapshot === 'object') {
    const enrichmentBlock = String(parentSnapshot.enrichmentBlock || '').trim();
    if (!enrichmentBlock) return empty;
    return {
      contextId: contextId || null,
      enrichmentBlock,
      referenceImageBuffers: [],
      contextPreview: {
        documentCount: Array.isArray(parentSnapshot.previews?.documents)
          ? parentSnapshot.previews.documents.length
          : 0,
        imageCount: Array.isArray(parentSnapshot.previews?.images)
          ? parentSnapshot.previews.images.length
          : Number(parentSnapshot.referenceImageCount) || 0,
      },
      contextSnapshot: parentSnapshot,
      usedLiveContext: false,
      pinContextId: null,
    };
  }

  if (contextId && requireLive) {
    throw new AppError(messages.IMAGE_GEN_CONTEXT_NOT_FOUND, 404);
  }

  return empty;
}

async function pinIfNeeded(contextId) {
  if (!contextId) return;
  await contextDao.pinContext(contextId);
}

module.exports = {
  createContext,
  getContext,
  deleteContext,
  resolveForGenerate,
  pinIfNeeded,
  serializeContext,
  appendContextBlock,
  withReferenceImageIndexHints,
  MAX_FILES,
  TTL_DAYS,
};
