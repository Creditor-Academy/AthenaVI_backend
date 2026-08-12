const { v4: uuidv4 } = require('uuid');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const {
  generateImage,
  editImage,
  generateImageWithReferences,
} = require('../../shared/services/ai');
const { getObjectBuffer } = require('../s3/s3.service');
const { persistWorkspaceAsset } = require('../asset/asset.service');
const prisma = require('../../shared/config/prismaClient');
const imageGenCredit = require('./imageGenCredit.service');
const imageGenDao = require('./imageGen.dao');
const rateLimit = require('./imageGenRateLimit.service');
const contextService = require('./imageGen.context.service');
const { listModels, resolveModel, estimateCredits } = require('./catalogs/models');
const {
  listFormats,
  resolveFormat,
  openaiSizeForFormat,
} = require('./catalogs/formats');
const { listStyles, resolveStyle } = require('./catalogs/styles');
const { buildImagePrompt } = require('./prompts/imageStyle.prompt');
const { buildInfographicPrompt } = require('./prompts/infographic.prompt');
const { buildSocialPrompt } = require('./prompts/social.prompt');
const { cropToFormat } = require('./socialCrop.service');
const { DOWNLOAD_FORMATS, sendDownload } = require('./imageGenExport.service');
const { IMAGE_GEN_FEATURE } = require('../../shared/config/imageGenCreditPricing');

const MODES = new Set(['image', 'infographic', 'social']);

function serializeGeneration(row) {
  if (!row) return row;
  const request = row.request && typeof row.request === 'object' ? row.request : {};
  return {
    id: row.id,
    workspaceId: row.workspaceId,
    userId: row.userId,
    mode: row.mode,
    modelId: row.modelId,
    formatId: row.formatId,
    styleId: row.styleId,
    prompt: row.prompt,
    revisedPrompt: row.revisedPrompt,
    request: row.request,
    parentId: row.parentId,
    rootId: row.rootId,
    action: row.action,
    assetId: row.assetId,
    contextId: row.contextId || request.contextId || null,
    contextPreview: request.contextPreview || null,
    s3Key: row.s3Key,
    url: row.url,
    openaiSize: row.openaiSize,
    exportWidth: row.exportWidth,
    exportHeight: row.exportHeight,
    creditsCharged: row.creditsCharged,
    status: row.status,
    createdAt: row.createdAt,
    asset: row.asset || null,
    downloadFormats: [...DOWNLOAD_FORMATS],
  };
}

function buildFinalPrompt({ mode, prompt, styleId, format, headline, subheadline, brandPalette, infographic }) {
  if (mode === 'infographic') {
    return buildInfographicPrompt({
      prompt,
      styleId,
      brandPalette,
      infographic,
    });
  }
  if (mode === 'social') {
    return buildSocialPrompt({
      prompt,
      styleId,
      format,
      headline,
      subheadline,
      brandPalette,
    });
  }
  return buildImagePrompt({ prompt, styleId });
}

function resolveRequestFormat({ mode, formatId }) {
  if (mode === 'social') {
    if (!formatId) {
      throw new AppError('formatId is required for social mode', 400);
    }
    const format = resolveFormat(formatId);
    if (!format || format.category !== 'social') {
      throw new AppError('Invalid social formatId', 400);
    }
    return format;
  }

  if (formatId) {
    const format = resolveFormat(formatId);
    if (!format) {
      throw new AppError('Invalid formatId', 400);
    }
    return format;
  }

  return resolveFormat('square');
}

function assertModeModelCompatible(mode, model) {
  if (!model.modes.includes(mode)) {
    throw new AppError(
      `Model ${model.id} does not support mode "${mode}". Choose a model that lists this mode.`,
      400
    );
  }
}

async function runPipeline({
  userId,
  workspace,
  mode,
  modelId,
  formatId,
  styleId,
  prompt,
  headline,
  subheadline,
  brandPalette,
  infographic,
  name,
  action,
  parentId,
  rootId,
  rateLimitFn,
  contextId = null,
  parentSnapshot = null,
}) {
  if (!MODES.has(mode)) {
    throw new AppError('Invalid mode. Use image, infographic, or social.', 400);
  }
  if (!prompt || !String(prompt).trim()) {
    if (mode === 'infographic' && infographic?.sections?.length) {
      // ok — sections carry content
    } else {
      throw new AppError('prompt is required', 400);
    }
  }

  const model = resolveModel(modelId);
  if (!model) {
    throw new AppError('Invalid modelId', 400);
  }
  assertModeModelCompatible(mode, model);

  if (styleId && !resolveStyle(styleId)) {
    throw new AppError('Invalid style', 400);
  }

  const format = resolveRequestFormat({ mode, formatId: formatId || null });
  const pricing = estimateCredits({ modelId: model.id, mode, isTweak: false });

  await rateLimitFn(userId, workspace.id);

  // Resolve context before credit check so invalid/expired contextId fails with 4xx
  // (not 402) and we don't assert affordability unnecessarily.
  const contextResult = await contextService.resolveForGenerate({
    contextId: contextId || null,
    workspace,
    userId,
    parentSnapshot: action === 'regenerate' ? parentSnapshot : null,
    requireLive: action === 'generate' && Boolean(contextId),
  });

  await imageGenCredit.assertAfford(workspace.id, userId, pricing.athenaCredits);

  const basePrompt = buildFinalPrompt({
    mode,
    prompt: prompt || '',
    styleId,
    format,
    headline,
    subheadline,
    brandPalette,
    infographic,
  });

  let enrichedPrompt = contextService.appendContextBlock(
    basePrompt,
    contextResult.enrichmentBlock
  );

  const referenceBuffers = contextResult.referenceImageBuffers || [];
  const useRefs = referenceBuffers.length > 0;
  if (useRefs) {
    enrichedPrompt = contextService.withReferenceImageIndexHints(
      enrichedPrompt,
      referenceBuffers.length
    );
  }

  const openaiSize = openaiSizeForFormat(format, model.openaiModel);
  const generated = useRefs
    ? await generateImageWithReferences({
        prompt: enrichedPrompt,
        referenceBuffers,
        model: model.openaiModel,
        quality: model.quality,
        size: openaiSize,
      })
    : await generateImage({
        prompt: enrichedPrompt,
        model: model.openaiModel,
        quality: model.quality,
        size: openaiSize,
      });

  const cropped = await cropToFormat(generated.buffer, format);
  const generationId = uuidv4();
  const assetName =
    (name && String(name).trim()) ||
    `ai-${mode}-${format?.id || 'square'}-${generationId.slice(0, 8)}.png`;

  const asset = await persistWorkspaceAsset({
    userId,
    workspace,
    buffer: cropped.buffer,
    contentType: 'image/png',
    originalName: assetName.endsWith('.png') ? assetName : `${assetName}.png`,
    name: assetName.endsWith('.png') ? assetName : `${assetName}.png`,
    source: 'ai_gen',
    stockMetadata: {
      generationId,
      mode,
      modelId: model.id,
      formatId: format?.id || null,
      styleId: styleId || null,
      action,
      contextId: contextResult.contextId || null,
    },
  });

  const resolvedRootId = rootId || parentId || generationId;
  const liveContextId = contextResult.usedLiveContext ? contextResult.contextId : null;
  const requestPayload = {
    mode,
    modelId: model.id,
    formatId: format?.id || null,
    styleId: styleId || null,
    prompt: prompt || '',
    headline: headline || null,
    subheadline: subheadline || null,
    brandPalette: brandPalette || null,
    infographic: infographic || null,
    name: assetName,
    contextId: liveContextId || contextResult.contextId || contextId || null,
    contextPreview: contextResult.contextPreview || null,
    contextSnapshot: contextResult.contextSnapshot || null,
  };

  const row = await imageGenDao.createGeneration({
    id: generationId,
    workspaceId: workspace.id,
    userId,
    mode,
    modelId: model.id,
    formatId: format?.id || null,
    styleId: styleId || null,
    prompt: prompt || enrichedPrompt,
    revisedPrompt: generated.revised_prompt || null,
    request: requestPayload,
    parentId: parentId || null,
    rootId: resolvedRootId,
    action,
    assetId: asset.id,
    contextId: liveContextId,
    s3Key: asset.key,
    url: asset.url,
    openaiSize,
    exportWidth: cropped.width,
    exportHeight: cropped.height,
    creditsCharged: 0,
    status: 'SUCCEEDED',
  });

  if (contextResult.pinContextId) {
    await contextService.pinIfNeeded(contextResult.pinContextId);
  }

  const charge = await imageGenCredit.chargeFlat({
    workspaceId: workspace.id,
    userId,
    feature: model.feature,
    idempotencyKey: `imageGen:${generationId}:${action}`,
    amountAc: pricing.athenaCredits,
    metadata: {
      generationId,
      mode,
      modelId: model.id,
      formatId: format?.id || null,
      action,
      contextId: liveContextId,
    },
  });

  const charged = charge?.pricing?.athenaCredits ?? pricing.athenaCredits;
  if (charged > 0) {
    await prisma.imageGeneration.update({
      where: { id: generationId },
      data: { creditsCharged: charged },
    });
    row.creditsCharged = charged;
  }

  return {
    generation: serializeGeneration({ ...row, asset }),
    asset,
    creditsCharged: charged,
    downloadFormats: [...DOWNLOAD_FORMATS],
  };
}

async function generate({ userId, workspace, body }) {
  return runPipeline({
    userId,
    workspace,
    mode: body.mode || 'image',
    modelId: body.modelId || 'gpt-image-1',
    formatId: body.formatId,
    styleId: body.style || body.styleId,
    prompt: body.prompt,
    headline: body.headline,
    subheadline: body.subheadline,
    brandPalette: body.brandPalette,
    infographic: body.infographic,
    name: body.name,
    action: 'generate',
    parentId: null,
    rootId: null,
    rateLimitFn: rateLimit.assertGenerateAllowed,
    contextId: body.contextId || null,
    parentSnapshot: null,
  });
}

async function regenerate({ userId, workspace, generationId, body = {} }) {
  const parent = await imageGenDao.findById(generationId, workspace.id);
  if (!parent) {
    throw new AppError(messages.IMAGE_GEN_NOT_FOUND, 404);
  }

  const prev = parent.request || {};
  const inheritedContextId =
    body.contextId !== undefined
      ? body.contextId || null
      : parent.contextId || prev.contextId || null;

  return runPipeline({
    userId,
    workspace,
    mode: body.mode || parent.mode || prev.mode || 'image',
    modelId: body.modelId || parent.modelId || prev.modelId || 'gpt-image-1',
    formatId:
      body.formatId !== undefined ? body.formatId : parent.formatId || prev.formatId,
    styleId:
      body.style !== undefined || body.styleId !== undefined
        ? body.style || body.styleId
        : parent.styleId || prev.styleId,
    prompt: body.prompt !== undefined ? body.prompt : parent.prompt || prev.prompt,
    headline:
      body.headline !== undefined ? body.headline : prev.headline,
    subheadline:
      body.subheadline !== undefined ? body.subheadline : prev.subheadline,
    brandPalette:
      body.brandPalette !== undefined ? body.brandPalette : prev.brandPalette,
    infographic:
      body.infographic !== undefined ? body.infographic : prev.infographic,
    name: body.name,
    action: 'regenerate',
    parentId: parent.id,
    rootId: parent.rootId || parent.id,
    rateLimitFn: rateLimit.assertRegenerateAllowed,
    contextId: inheritedContextId,
    parentSnapshot: prev.contextSnapshot || null,
  });
}

async function tweak({ userId, workspace, generationId, instruction }) {
  if (!instruction || !String(instruction).trim()) {
    throw new AppError('instruction is required', 400);
  }

  const parent = await imageGenDao.findById(generationId, workspace.id);
  if (!parent) {
    throw new AppError(messages.IMAGE_GEN_NOT_FOUND, 404);
  }

  const model = resolveModel(parent.modelId) || resolveModel('gpt-image-1');
  const format = parent.formatId ? resolveFormat(parent.formatId) : resolveFormat('square');
  const pricing = estimateCredits({
    modelId: model.supportsEdit ? model.id : 'gpt-image-1',
    mode: parent.mode,
    isTweak: true,
  });

  await rateLimit.assertRegenerateAllowed(userId, workspace.id);
  await imageGenCredit.assertAfford(workspace.id, userId, pricing.athenaCredits);

  const sourceBuffer = await getObjectBuffer(parent.s3Key);
  const openaiSize = openaiSizeForFormat(format, 'gpt-image-1');
  const edited = await editImage({
    imageBuffer: sourceBuffer,
    instruction: String(instruction).trim(),
    model: 'gpt-image-1',
    quality: model.quality === 'high' ? 'high' : 'medium',
    size: openaiSize,
  });

  const cropped = await cropToFormat(edited.buffer, format);
  const generationIdNew = uuidv4();
  const assetName = `ai-tweak-${generationIdNew.slice(0, 8)}.png`;

  const asset = await persistWorkspaceAsset({
    userId,
    workspace,
    buffer: cropped.buffer,
    contentType: 'image/png',
    originalName: assetName,
    name: assetName,
    source: 'ai_gen',
    stockMetadata: {
      generationId: generationIdNew,
      mode: parent.mode,
      modelId: model.id,
      formatId: format?.id || null,
      action: 'tweak',
      parentId: parent.id,
    },
  });

  const prev = parent.request || {};
  const requestPayload = {
    ...prev,
    tweakInstruction: String(instruction).trim(),
  };

  const row = await imageGenDao.createGeneration({
    id: generationIdNew,
    workspaceId: workspace.id,
    userId,
    mode: parent.mode,
    modelId: model.id,
    formatId: format?.id || null,
    styleId: parent.styleId,
    prompt: parent.prompt,
    revisedPrompt: edited.revised_prompt || null,
    request: requestPayload,
    parentId: parent.id,
    rootId: parent.rootId || parent.id,
    action: 'tweak',
    assetId: asset.id,
    contextId: parent.contextId || prev.contextId || null,
    s3Key: asset.key,
    url: asset.url,
    openaiSize,
    exportWidth: cropped.width,
    exportHeight: cropped.height,
    creditsCharged: 0,
    status: 'SUCCEEDED',
  });

  const charge = await imageGenCredit.chargeFlat({
    workspaceId: workspace.id,
    userId,
    feature: IMAGE_GEN_FEATURE.TWEAK,
    idempotencyKey: `imageGen:${generationIdNew}:tweak`,
    amountAc: pricing.athenaCredits,
    metadata: {
      generationId: generationIdNew,
      parentId: parent.id,
      action: 'tweak',
      modelId: model.id,
    },
  });

  const charged = charge?.pricing?.athenaCredits ?? pricing.athenaCredits;
  if (charged > 0) {
    await prisma.imageGeneration.update({
      where: { id: generationIdNew },
      data: { creditsCharged: charged },
    });
    row.creditsCharged = charged;
  }

  return {
    generation: serializeGeneration({ ...row, asset }),
    asset,
    creditsCharged: charged,
    downloadFormats: [...DOWNLOAD_FORMATS],
  };
}

async function getGeneration({ workspace, generationId }) {
  const row = await imageGenDao.findById(generationId, workspace.id);
  if (!row) {
    throw new AppError(messages.IMAGE_GEN_NOT_FOUND, 404);
  }
  return serializeGeneration(row);
}

async function listGenerations({ userId, workspace, query = {} }) {
  const rows = await imageGenDao.listGenerations({
    workspaceId: workspace.id,
    userId,
    isPrivate: workspace.type === 'PRIVATE',
    take: query.take,
    skip: query.skip,
    mode: query.mode,
  });
  return rows.map(serializeGeneration);
}

function creditEstimate({ modelId, mode, tweak }) {
  return estimateCredits({
    modelId: modelId || 'gpt-image-1',
    mode: mode || 'image',
    isTweak: tweak === true || tweak === 'true',
  });
}

async function downloadGeneration({ req, res, workspace, generationId, format }) {
  const row = await imageGenDao.findById(generationId, workspace.id);
  if (!row) {
    throw new AppError(messages.IMAGE_GEN_NOT_FOUND, 404);
  }
  const filenameBase = row.asset?.name || `image-${row.id}`;
  return sendDownload(req, res, {
    s3Key: row.s3Key,
    format,
    filenameBase,
  });
}

module.exports = {
  listModels,
  listFormats,
  listStyles,
  creditEstimate,
  generate,
  regenerate,
  tweak,
  getGeneration,
  listGenerations,
  downloadGeneration,
  DOWNLOAD_FORMATS,
};
