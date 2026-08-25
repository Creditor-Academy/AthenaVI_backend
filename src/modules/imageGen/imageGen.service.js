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
const projectDao = require('../project/project.dao');
const imageGenCredit = require('./imageGenCredit.service');
const imageGenDao = require('./imageGen.dao');
const threadDao = require('./imageGen.thread.dao');
const messageDao = require('./imageGen.message.dao');
const rateLimit = require('./imageGenRateLimit.service');
const contextService = require('./imageGen.context.service');
const { listModels, resolveModel, estimateCredits, defaultModelIdForMode } = require('./catalogs/models');
const {
  listFormats,
  resolveFormat,
  openaiSizeForFormat,
} = require('./catalogs/formats');
const { listStyles, resolveStyle } = require('./catalogs/styles');
const { listArchetypes } = require('./catalogs/archetypes');
const { buildImagePrompt } = require('./prompts/imageStyle.prompt');
const { buildChatEditInstruction } = require('./prompts/chatEdit.prompt');
const { cropToFormat } = require('./socialCrop.service');
const { DOWNLOAD_FORMATS, sendDownload } = require('./imageGenExport.service');
const { resolveAssetFilename } = require('./imageGenFilename');
const {
  IMAGE_GEN_FEATURE,
  getInfographicAc,
} = require('../../shared/config/imageGenCreditPricing');
const infographicService = require('./infographic.service');

const STUDIO_MODES = Object.freeze(['image', 'infographic']);

function serializeGeneration(row) {
  if (!row) return row;
  const request = row.request && typeof row.request === 'object' ? row.request : {};
  const infographicSpec = request.infographicSpec || null;
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
    threadId: row.threadId || null,
    contextId: row.contextId || request.contextId || null,
    contextPreview: request.contextPreview || null,
    infographicSpec,
    archetype: infographicSpec?.archetype || request.archetypeHint || null,
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

function serializeHead(generation) {
  if (!generation) return null;
  const request =
    generation.request && typeof generation.request === 'object' ? generation.request : {};
  return {
    generationId: generation.id,
    url: generation.url,
    action: generation.action,
    mode: generation.mode || null,
    archetype: request.infographicSpec?.archetype || request.archetypeHint || null,
    createdAt: generation.createdAt,
    asset: generation.asset || null,
  };
}

function serializeMessage(row) {
  if (!row) return row;
  const generation = row.generation || null;
  return {
    id: row.id,
    threadId: row.threadId,
    userId: row.userId,
    role: row.role,
    type: row.type,
    content: row.content,
    generationId: row.generationId || null,
    creditsCharged: row.creditsCharged,
    createdAt: row.createdAt,
    url: generation?.url || generation?.asset?.url || null,
    asset: generation?.asset || null,
  };
}

function serializeThread(row, { includeMessages = false } = {}) {
  if (!row) return row;
  const head = serializeHead(row.headGeneration);
  const headRequest =
    row.headGeneration?.request && typeof row.headGeneration.request === 'object'
      ? row.headGeneration.request
      : {};
  const mode = row.headGeneration?.mode || null;
  const archetype =
    headRequest.infographicSpec?.archetype || headRequest.archetypeHint || null;
  const payload = {
    id: row.id,
    threadId: row.id,
    workspaceId: row.workspaceId,
    folderId: row.folderId,
    userId: row.userId,
    title: row.title,
    mode,
    archetype,
    rootGenerationId: row.rootGenerationId,
    headGenerationId: row.headGenerationId,
    contextId: row.contextId || null,
    modelId: row.modelId || null,
    formatId: row.formatId || null,
    styleId: row.styleId || null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    head,
    messageCount: row._count?.messages ?? (row.messages ? row.messages.length : 0),
    versionCount: row._count?.generations ?? 0,
    downloadFormats: [...DOWNLOAD_FORMATS],
  };
  if (includeMessages) {
    payload.messages = Array.isArray(row.messages) ? row.messages.map(serializeMessage) : [];
  }
  return payload;
}

function threadActions(workspaceId, generation, threadId) {
  const generationId = generation?.id;
  return {
    viewUrl: generation?.url || null,
    downloadPath: generationId
      ? `/api/image-gen/workspaces/${workspaceId}/generations/${generationId}/download`
      : null,
    threadId: threadId || generation?.threadId || null,
  };
}

function withThreadPayload(result, thread, workspaceId) {
  const generation = result.generation;
  const serialized = serializeThread(thread);
  return {
    ...result,
    generation: serializeGeneration({
      ...(generation || {}),
      threadId: thread?.id || generation?.threadId || null,
    }),
    thread: serialized,
    actions: threadActions(workspaceId, generation, thread?.id),
  };
}

function titleFromPrompt(prompt) {
  const raw = String(prompt || '').trim().replace(/\s+/g, ' ');
  if (!raw) return 'Untitled image';
  return raw.length > 80 ? `${raw.slice(0, 79)}…` : raw;
}

async function assertFolderInWorkspace(folderId, workspaceId) {
  const folder = await projectDao.findFolderById(folderId);
  if (!folder || folder.workspaceId !== workspaceId) {
    throw new AppError(messages.FOLDER_NOT_FOUND, 404);
  }
  return folder;
}

function resolveRequestFormat(formatId) {
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

function requireStudioGeneration(row, { notFoundIfWrongMode = false, allowedModes = STUDIO_MODES } = {}) {
  if (!row) {
    throw new AppError(messages.IMAGE_GEN_NOT_FOUND, 404);
  }
  const modes = Array.isArray(allowedModes) && allowedModes.length ? allowedModes : STUDIO_MODES;
  if (!modes.includes(row.mode)) {
    if (notFoundIfWrongMode) {
      throw new AppError(messages.IMAGE_GEN_NOT_FOUND, 404);
    }
    throw new AppError(messages.IMAGE_GEN_MODE_INVALID, 400);
  }
  return row;
}

function requireThread(row) {
  if (!row) {
    throw new AppError(messages.IMAGE_GEN_THREAD_NOT_FOUND, 404);
  }
  return row;
}

function assertThreadAccessible(row, workspace, userId) {
  requireThread(row);
  if (workspace.type === 'PRIVATE' && row.userId !== userId) {
    throw new AppError(messages.IMAGE_GEN_THREAD_NOT_FOUND, 404);
  }
}

async function loadThread(threadId, workspace, userId) {
  const row = await threadDao.findById(threadId, workspace.id, {
    userId,
    isPrivate: workspace.type === 'PRIVATE',
  });
  assertThreadAccessible(row, workspace, userId);
  return row;
}

async function findFirstFolderId(workspaceId) {
  const folder = await prisma.folder.findFirst({
    where: { workspaceId },
    orderBy: { createdAt: 'asc' },
    select: { id: true },
  });
  return folder?.id || null;
}

async function attachHopMessages({
  threadId,
  userId,
  type,
  userContent,
  generationId,
  creditsCharged,
}) {
  await messageDao.createMessages([
    {
      threadId,
      userId,
      role: 'user',
      type,
      content: String(userContent || ''),
      generationId: null,
      creditsCharged: 0,
    },
    {
      threadId,
      userId,
      role: 'assistant',
      type,
      content: '',
      generationId,
      creditsCharged: creditsCharged || 0,
    },
  ]);
}

async function advanceThreadHead(threadId, generation) {
  await imageGenDao.setThreadId(generation.id, threadId);
  return threadDao.updateThread(threadId, {
    headGenerationId: generation.id,
    modelId: generation.modelId || undefined,
    formatId: generation.formatId,
    styleId: generation.styleId,
    contextId: generation.contextId,
    updatedAt: new Date(),
  });
}

async function createThreadForGeneration({
  workspace,
  folderId,
  userId,
  generation,
  prompt,
  rootGenerationId = null,
}) {
  const thread = await threadDao.createThread({
    workspaceId: workspace.id,
    folderId,
    userId,
    title: titleFromPrompt(prompt || generation.prompt),
    rootGenerationId: rootGenerationId || generation.id,
    headGenerationId: generation.id,
    contextId: generation.contextId || null,
    modelId: generation.modelId,
    formatId: generation.formatId,
    styleId: generation.styleId,
  });
  await imageGenDao.setThreadId(generation.id, thread.id);
  await attachHopMessages({
    threadId: thread.id,
    userId,
    type: 'prompt',
    userContent: prompt || generation.prompt || '',
    generationId: generation.id,
    creditsCharged: generation.creditsCharged,
  });
  return threadDao.findById(thread.id, workspace.id);
}

async function ensureThreadForParent({ parent, workspace, userId, folderId }) {
  if (parent.threadId) {
    const existing = await threadDao.findById(parent.threadId, workspace.id, {
      userId,
      isPrivate: workspace.type === 'PRIVATE',
    });
    if (existing) return existing;
  }

  const rootId = parent.rootId || parent.id;
  const byRoot = await threadDao.findByRootGenerationId(rootId, workspace.id);
  if (byRoot) {
    await imageGenDao.setThreadId(parent.id, byRoot.id);
    return threadDao.findById(byRoot.id, workspace.id);
  }

  const resolvedFolderId = folderId || (await findFirstFolderId(workspace.id));
  if (!resolvedFolderId) {
    throw new AppError(messages.FOLDER_NOT_FOUND, 404);
  }
  await assertFolderInWorkspace(resolvedFolderId, workspace.id);
  return createThreadForGeneration({
    workspace,
    folderId: resolvedFolderId,
    userId: parent.userId || userId,
    generation: parent,
    prompt: parent.prompt,
    rootGenerationId: parent.rootId || parent.id,
  });
}

async function runPipeline({
  userId,
  workspace,
  mode: modeInput = 'image',
  modelId,
  formatId,
  styleId,
  styleHint = null,
  archetypeHint = null,
  prompt,
  brandPalette,
  name,
  action,
  parentId,
  rootId,
  rateLimitFn,
  contextId = null,
  parentSnapshot = null,
  threadId = null,
  infographicSpec: providedSpec = null,
  infographicWarnings: providedWarnings = null,
  skipSpecBuild = false,
}) {
  const mode = modeInput === 'infographic' ? 'infographic' : 'image';
  if (!prompt || !String(prompt).trim()) {
    throw new AppError('prompt is required', 400);
  }

  const model = resolveModel(modelId);
  if (!model) {
    throw new AppError('Invalid modelId', 400);
  }
  assertModeModelCompatible(mode, model);

  if (styleId && !resolveStyle(styleId)) {
    throw new AppError('Invalid style', 400);
  }

  const format =
    mode === 'infographic'
      ? resolveRequestFormat(formatId || 'landscape')
      : resolveRequestFormat(formatId || null);
  const pricing = estimateCredits({ modelId: model.id, mode, isTweak: false });

  await rateLimitFn(userId, workspace.id);

  const contextResult = await contextService.resolveForGenerate({
    contextId: contextId || null,
    workspace,
    userId,
    parentSnapshot: action === 'regenerate' ? parentSnapshot : null,
    requireLive: action === 'generate' && Boolean(contextId),
  });

  await imageGenCredit.assertAfford(workspace.id, userId, pricing.athenaCredits);

  const referenceBuffers = contextResult.referenceImageBuffers || [];
  const useRefs = referenceBuffers.length > 0;

  let enrichedPrompt;
  let infographicSpec = providedSpec || null;
  let infographicWarnings = Array.isArray(providedWarnings) ? [...providedWarnings] : [];
  let renderPromptPreview = null;

  if (mode === 'infographic') {
    if (!skipSpecBuild || !infographicSpec) {
      const built = await infographicService.buildSpec({
        prompt: String(prompt).trim(),
        contextText: contextResult.enrichmentBlock || '',
        archetypeHint: archetypeHint || null,
        styleHint:
          infographicService.mergeStyleHint({
            styleHint,
            style: styleId,
            styleId,
          }),
        format,
      });
      infographicSpec = built.spec;
      infographicWarnings = [...infographicWarnings, ...(built.warnings || [])];
    } else if (infographicSpec && !infographicSpec.orientation) {
      infographicSpec = { ...infographicSpec, orientation: format.id };
    }

    enrichedPrompt = infographicService.buildRenderPrompt({
      spec: infographicSpec,
      format,
      hasReferences: useRefs,
    });
    renderPromptPreview = String(enrichedPrompt).slice(0, 500);
  } else {
    const basePrompt = buildImagePrompt({ prompt: prompt || '', styleId });
    enrichedPrompt = contextService.appendContextBlock(
      basePrompt,
      contextResult.enrichmentBlock
    );
  }

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

  const cropped = await cropToFormat(generated.buffer, format, {
    fit: mode === 'infographic' ? 'contain' : 'cover',
  });
  const revisedPrompt = generated.revised_prompt || null;

  const generationId = uuidv4();
  const assetName = resolveAssetFilename({
    name,
    prompt,
    mode,
  });

  const asset = await persistWorkspaceAsset({
    userId,
    workspace,
    buffer: cropped.buffer,
    contentType: 'image/png',
    originalName: assetName,
    name: assetName,
    source: 'ai_gen',
    stockMetadata: {
      generationId,
      mode,
      modelId: model.id,
      formatId: format?.id || null,
      styleId: styleId || null,
      action,
      contextId: contextResult.contextId || null,
      threadId: threadId || null,
      archetype: infographicSpec?.archetype || null,
    },
  });

  const resolvedRootId = rootId || parentId || generationId;
  const liveContextId = contextResult.usedLiveContext ? contextResult.contextId : null;
  const chargeFeature =
    mode === 'infographic' ? IMAGE_GEN_FEATURE.INFOGRAPHIC : model.feature;
  const chargeAmount =
    mode === 'infographic' ? getInfographicAc(model.id) : pricing.athenaCredits;

  const requestPayload = {
    mode,
    modelId: model.id,
    formatId: format?.id || null,
    styleId: styleId || null,
    styleHint: styleHint || null,
    archetypeHint: archetypeHint || null,
    prompt: prompt || '',
    brandPalette: brandPalette || null,
    name: assetName,
    contextId: liveContextId || contextResult.contextId || contextId || null,
    contextPreview: contextResult.contextPreview || null,
    contextSnapshot: contextResult.contextSnapshot || null,
    ...(mode === 'infographic'
      ? {
          infographicSpec,
          warnings: infographicWarnings,
          renderPromptPreview,
        }
      : {}),
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
    revisedPrompt,
    request: requestPayload,
    parentId: parentId || null,
    rootId: resolvedRootId,
    action,
    assetId: asset.id,
    contextId: liveContextId,
    threadId: threadId || null,
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
    feature: chargeFeature,
    idempotencyKey: `imageGen:${generationId}:${action}`,
    amountAc: chargeAmount,
    metadata: {
      generationId,
      mode,
      modelId: model.id,
      formatId: format?.id || null,
      action,
      contextId: liveContextId,
      threadId: threadId || null,
      archetype: infographicSpec?.archetype || null,
    },
  });

  const charged = charge?.pricing?.athenaCredits ?? chargeAmount;
  if (charged > 0) {
    await prisma.imageGeneration.update({
      where: { id: generationId },
      data: { creditsCharged: charged },
    });
    row.creditsCharged = charged;
  }

  return {
    generation: serializeGeneration({ ...row, asset, threadId: threadId || row.threadId }),
    asset,
    creditsCharged: charged,
    downloadFormats: [...DOWNLOAD_FORMATS],
  };
}

async function runTweakOnParent({
  userId,
  workspace,
  parent,
  instruction,
  editPrompt,
  threadId = null,
}) {
  if (!instruction || !String(instruction).trim()) {
    throw new AppError('instruction is required', 400);
  }

  const mode = parent.mode === 'infographic' ? 'infographic' : 'image';
  const model =
    resolveModel(parent.modelId) ||
    resolveModel(mode === 'infographic' ? 'gpt-image-1-hd' : 'gpt-image-1');
  const format = parent.formatId
    ? resolveFormat(parent.formatId)
    : resolveRequestFormat(mode === 'infographic' ? 'landscape' : null);
  const pricing = estimateCredits({
    modelId: model.supportsEdit ? model.id : model.id,
    mode,
    isTweak: true,
  });

  await rateLimit.assertRegenerateAllowed(userId, workspace.id);
  await imageGenCredit.assertAfford(workspace.id, userId, pricing.athenaCredits);

  const sourceBuffer = await getObjectBuffer(parent.s3Key);
  const openaiSize = openaiSizeForFormat(format, 'gpt-image-1');
  const openaiInstruction = String(editPrompt || instruction).trim();
  const edited = await editImage({
    imageBuffer: sourceBuffer,
    instruction: openaiInstruction,
    model: 'gpt-image-1',
    quality: model.quality === 'high' ? 'high' : 'medium',
    size: openaiSize,
  });

  const cropped = await cropToFormat(edited.buffer, format, {
    fit: mode === 'infographic' ? 'contain' : 'cover',
  });
  const generationIdNew = uuidv4();
  const assetName = resolveAssetFilename({
    prompt: parent.prompt,
    mode,
    instruction: String(instruction).trim(),
  });

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
      mode,
      modelId: model.id,
      formatId: format?.id || null,
      action: 'tweak',
      parentId: parent.id,
      threadId: threadId || parent.threadId || null,
    },
  });

  const prev = parent.request || {};
  const chargeFeature =
    mode === 'infographic' ? IMAGE_GEN_FEATURE.INFOGRAPHIC : IMAGE_GEN_FEATURE.TWEAK;
  const chargeAmount =
    mode === 'infographic' ? getInfographicAc(model.id) : pricing.athenaCredits;

  const requestPayload = {
    mode,
    modelId: model.id,
    formatId: format?.id || null,
    styleId: parent.styleId || prev.styleId || null,
    prompt: parent.prompt,
    brandPalette: prev.brandPalette || null,
    name: assetName,
    contextId: parent.contextId || prev.contextId || null,
    contextPreview: prev.contextPreview || null,
    contextSnapshot: prev.contextSnapshot || null,
    tweakInstruction: String(instruction).trim(),
    ...(mode === 'infographic'
      ? {
          infographicSpec: prev.infographicSpec || null,
          pixelEdited: true,
          warnings: prev.warnings || [],
        }
      : {}),
  };

  const row = await imageGenDao.createGeneration({
    id: generationIdNew,
    workspaceId: workspace.id,
    userId,
    mode,
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
    threadId: threadId || parent.threadId || null,
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
    feature: chargeFeature,
    idempotencyKey: `imageGen:${generationIdNew}:tweak`,
    amountAc: chargeAmount,
    metadata: {
      generationId: generationIdNew,
      parentId: parent.id,
      action: 'tweak',
      modelId: model.id,
      mode,
      threadId: threadId || parent.threadId || null,
      pixelEdited: mode === 'infographic',
    },
  });

  const charged = charge?.pricing?.athenaCredits ?? chargeAmount;
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

async function generate({ userId, workspace, body }) {
  const mode = body.mode === 'infographic' ? 'infographic' : 'image';
  if (!STUDIO_MODES.includes(mode)) {
    throw new AppError(messages.IMAGE_GEN_MODE_INVALID, 400);
  }
  await assertFolderInWorkspace(body.folderId, workspace.id);

  const styleHint = infographicService.mergeStyleHint({
    styleHint: body.styleHint,
    style: body.style,
    styleId: body.styleId,
  });

  const result = await runPipeline({
    userId,
    workspace,
    mode,
    modelId: defaultModelIdForMode(mode, body.modelId),
    formatId:
      body.formatId ||
      (mode === 'infographic' ? 'landscape' : undefined),
    styleId: body.style || body.styleId,
    styleHint,
    archetypeHint: body.archetypeHint || null,
    prompt: body.prompt,
    brandPalette: body.brandPalette,
    name: body.name,
    action: 'generate',
    parentId: null,
    rootId: null,
    rateLimitFn: rateLimit.assertGenerateAllowed,
    contextId: body.contextId || null,
    parentSnapshot: null,
  });

  const thread = await createThreadForGeneration({
    workspace,
    folderId: body.folderId,
    userId,
    generation: result.generation,
    prompt: body.prompt,
  });

  return withThreadPayload(result, thread, workspace.id);
}

function shouldRebuildInfographicSpec(body = {}, prev = {}) {
  if (body.prompt !== undefined && body.prompt !== prev.prompt) return true;
  if (body.archetypeHint !== undefined && body.archetypeHint !== prev.archetypeHint) {
    return true;
  }
  if (body.styleHint !== undefined && body.styleHint !== prev.styleHint) return true;
  if (body.style !== undefined || body.styleId !== undefined) {
    const nextStyle = body.style || body.styleId;
    if (nextStyle !== prev.styleId) return true;
  }
  if (body.contextId !== undefined && body.contextId !== prev.contextId) return true;
  return false;
}

async function regenerate({ userId, workspace, generationId, body = {} }) {
  const parent = requireStudioGeneration(
    await imageGenDao.findById(generationId, workspace.id)
  );

  const prev = parent.request || {};
  const mode =
    body.mode === 'infographic' || body.mode === 'image'
      ? body.mode
      : parent.mode === 'infographic'
        ? 'infographic'
        : 'image';

  if (body.mode && body.mode !== parent.mode) {
    throw new AppError(messages.IMAGE_GEN_MODE_MISMATCH, 400);
  }

  const inheritedContextId =
    body.contextId !== undefined
      ? body.contextId || null
      : parent.contextId || prev.contextId || null;

  const thread = await ensureThreadForParent({ parent, workspace, userId });
  const prompt = body.prompt !== undefined ? body.prompt : parent.prompt || prev.prompt;

  const styleHint = infographicService.mergeStyleHint({
    styleHint:
      body.styleHint !== undefined ? body.styleHint : prev.styleHint,
    style: body.style,
    styleId: body.styleId !== undefined ? body.styleId : parent.styleId || prev.styleId,
  });

  const rebuildSpec =
    mode === 'infographic' &&
    (shouldRebuildInfographicSpec(body, prev) || !prev.infographicSpec);

  const result = await runPipeline({
    userId,
    workspace,
    mode,
    modelId:
      body.modelId ||
      parent.modelId ||
      prev.modelId ||
      defaultModelIdForMode(mode),
    formatId:
      body.formatId !== undefined
        ? body.formatId
        : parent.formatId || prev.formatId || (mode === 'infographic' ? 'landscape' : null),
    styleId:
      body.style !== undefined || body.styleId !== undefined
        ? body.style || body.styleId
        : parent.styleId || prev.styleId,
    styleHint,
    archetypeHint:
      body.archetypeHint !== undefined
        ? body.archetypeHint
        : prev.archetypeHint || prev.infographicSpec?.archetype || null,
    prompt,
    brandPalette:
      body.brandPalette !== undefined ? body.brandPalette : prev.brandPalette,
    name: body.name,
    action: 'regenerate',
    parentId: parent.id,
    rootId: parent.rootId || parent.id,
    rateLimitFn: rateLimit.assertRegenerateAllowed,
    contextId: inheritedContextId,
    parentSnapshot: prev.contextSnapshot || null,
    threadId: thread.id,
    infographicSpec: rebuildSpec ? null : prev.infographicSpec || null,
    infographicWarnings: prev.warnings || null,
    skipSpecBuild: mode === 'infographic' && !rebuildSpec && Boolean(prev.infographicSpec),
  });

  await attachHopMessages({
    threadId: thread.id,
    userId,
    type: 'regenerate',
    userContent: prompt || 'Regenerate',
    generationId: result.generation.id,
    creditsCharged: result.creditsCharged,
  });
  const updated = await advanceThreadHead(thread.id, result.generation);
  return withThreadPayload(result, updated, workspace.id);
}

async function runInfographicSpecEdit({
  userId,
  workspace,
  parent,
  instruction,
  threadId,
}) {
  const prev = parent.request || {};
  const existingSpec = prev.infographicSpec;
  if (!existingSpec) {
    throw new AppError(messages.IMAGE_GEN_SPEC_INVALID, 400);
  }

  const format = parent.formatId
    ? resolveFormat(parent.formatId)
    : resolveRequestFormat('landscape');

  const patched = await infographicService.patchSpec({
    spec: existingSpec,
    instruction,
    format,
  });

  return runPipeline({
    userId,
    workspace,
    mode: 'infographic',
    modelId: parent.modelId || defaultModelIdForMode('infographic'),
    formatId: format?.id || 'landscape',
    styleId: parent.styleId || prev.styleId,
    styleHint: prev.styleHint || null,
    archetypeHint: patched.spec.archetype || prev.archetypeHint,
    prompt: parent.prompt,
    brandPalette: prev.brandPalette,
    name: prev.name,
    action: 'tweak',
    parentId: parent.id,
    rootId: parent.rootId || parent.id,
    rateLimitFn: rateLimit.assertRegenerateAllowed,
    contextId: parent.contextId || prev.contextId || null,
    parentSnapshot: prev.contextSnapshot || null,
    threadId,
    infographicSpec: patched.spec,
    infographicWarnings: patched.warnings,
    skipSpecBuild: true,
  });
}

async function tweak({ userId, workspace, generationId, instruction, editMode = null }) {
  const parent = requireStudioGeneration(
    await imageGenDao.findById(generationId, workspace.id)
  );
  const thread = await ensureThreadForParent({ parent, workspace, userId });

  let result;
  if (parent.mode === 'infographic') {
    const route = await infographicService.classifyEdit({ instruction, editMode });
    if (route === 'spec') {
      result = await runInfographicSpecEdit({
        userId,
        workspace,
        parent,
        instruction,
        threadId: thread.id,
      });
    } else {
      result = await runTweakOnParent({
        userId,
        workspace,
        parent,
        instruction,
        editPrompt: instruction,
        threadId: thread.id,
      });
    }
  } else {
    result = await runTweakOnParent({
      userId,
      workspace,
      parent,
      instruction,
      editPrompt: instruction,
      threadId: thread.id,
    });
  }

  await attachHopMessages({
    threadId: thread.id,
    userId,
    type: 'tweak',
    userContent: instruction,
    generationId: result.generation.id,
    creditsCharged: result.creditsCharged,
  });
  const updated = await advanceThreadHead(thread.id, result.generation);
  return withThreadPayload(result, updated, workspace.id);
}

async function sendThreadMessage({
  userId,
  workspace,
  threadId,
  content,
  fromGenerationId = null,
  editMode = null,
}) {
  if (!content || !String(content).trim()) {
    throw new AppError('content is required', 400);
  }

  const thread = await loadThread(threadId, workspace, userId);
  const parentId = fromGenerationId || thread.headGenerationId;
  const parent = requireStudioGeneration(
    await imageGenDao.findById(parentId, workspace.id)
  );

  if (parent.threadId && parent.threadId !== thread.id) {
    throw new AppError('Generation does not belong to this thread', 400);
  }
  if (!parent.threadId && parent.rootId && parent.rootId !== thread.rootGenerationId) {
    const rootOk =
      parent.id === thread.rootGenerationId || parent.rootId === thread.rootGenerationId;
    if (!rootOk) {
      throw new AppError('Generation does not belong to this thread', 400);
    }
  }

  // Sticky thread mode: stay on the parent's mode
  let result;
  if (parent.mode === 'infographic') {
    const route = await infographicService.classifyEdit({
      instruction: String(content).trim(),
      editMode,
    });
    if (route === 'spec') {
      result = await runInfographicSpecEdit({
        userId,
        workspace,
        parent,
        instruction: String(content).trim(),
        threadId: thread.id,
      });
    } else {
      result = await runTweakOnParent({
        userId,
        workspace,
        parent,
        instruction: String(content).trim(),
        editPrompt: String(content).trim(),
        threadId: thread.id,
      });
    }
  } else {
    const priorRows = await messageDao.listUserMessages(thread.id, { take: 12 });
    const priorUserTurns = [...priorRows].reverse().map((row) => row.content);
    let editPrompt = buildChatEditInstruction({
      originalPrompt: parent.prompt || thread.title,
      styleId: thread.styleId || parent.styleId,
      priorUserTurns,
      latestInstruction: String(content).trim(),
    });

    const snapshot =
      parent.request && typeof parent.request === 'object'
        ? parent.request.contextSnapshot
        : null;
    if (snapshot?.enrichmentBlock) {
      editPrompt = contextService.appendContextBlock(editPrompt, snapshot.enrichmentBlock);
      if (editPrompt.length > 4000) {
        editPrompt = editPrompt.slice(0, 4000);
      }
    }

    result = await runTweakOnParent({
      userId,
      workspace,
      parent,
      instruction: String(content).trim(),
      editPrompt,
      threadId: thread.id,
    });
  }

  await attachHopMessages({
    threadId: thread.id,
    userId,
    type: 'tweak',
    userContent: String(content).trim(),
    generationId: result.generation.id,
    creditsCharged: result.creditsCharged,
  });
  const updated = await advanceThreadHead(thread.id, result.generation);
  return withThreadPayload(result, updated, workspace.id);
}

async function listThreads({ userId, workspace, query = {} }) {
  if (query.folderId) {
    await assertFolderInWorkspace(query.folderId, workspace.id);
  }
  const rows = await threadDao.listThreads({
    workspaceId: workspace.id,
    userId,
    isPrivate: workspace.type === 'PRIVATE',
    folderId: query.folderId,
    take: query.take,
    skip: query.skip,
  });
  return rows.map((row) => serializeThread(row));
}

async function getThread({ userId, workspace, threadId }) {
  const row = await loadThread(threadId, workspace, userId);
  return serializeThread(row, { includeMessages: true });
}

async function renameThread({ userId, workspace, threadId, title }) {
  const row = await loadThread(threadId, workspace, userId);
  const nextTitle = String(title || '').trim();
  if (!nextTitle) {
    throw new AppError('title is required', 400);
  }
  const updated = await threadDao.updateThread(row.id, { title: nextTitle.slice(0, 255) });
  return serializeThread(updated);
}

async function moveThread({ userId, workspace, threadId, folderId }) {
  const row = await loadThread(threadId, workspace, userId);
  await assertFolderInWorkspace(folderId, workspace.id);
  const updated = await threadDao.updateThread(row.id, { folderId });
  return serializeThread(updated);
}

async function deleteThread({ userId, workspace, threadId }) {
  const row = await loadThread(threadId, workspace, userId);
  await threadDao.unlinkGenerations(row.id);
  await threadDao.deleteThread(row.id);
  return { deleted: true };
}

async function getGeneration({ workspace, generationId }) {
  const row = await imageGenDao.findById(generationId, workspace.id);
  requireStudioGeneration(row, { notFoundIfWrongMode: true });
  return serializeGeneration(row);
}

async function listGenerations({ userId, workspace, query = {} }) {
  const modeFilter =
    query.mode === 'image' || query.mode === 'infographic' ? query.mode : undefined;
  const rows = await imageGenDao.listGenerations({
    workspaceId: workspace.id,
    userId,
    isPrivate: workspace.type === 'PRIVATE',
    take: query.take,
    skip: query.skip,
    mode: modeFilter,
    threadId: query.threadId,
  });
  // When mode omitted, return both studio modes (filter out any legacy unknown modes)
  const filtered = modeFilter
    ? rows
    : rows.filter((row) => STUDIO_MODES.includes(row.mode));
  return filtered.map(serializeGeneration);
}

function creditEstimate({ modelId, mode, tweak }) {
  const resolvedMode = mode === 'infographic' ? 'infographic' : 'image';
  if (mode && !STUDIO_MODES.includes(mode)) {
    throw new AppError(messages.IMAGE_GEN_MODE_INVALID, 400);
  }
  return estimateCredits({
    modelId,
    mode: resolvedMode,
    isTweak: tweak === true || tweak === 'true',
  });
}

async function downloadGeneration({ req, res, workspace, generationId, format }) {
  const row = await imageGenDao.findById(generationId, workspace.id);
  requireStudioGeneration(row, { notFoundIfWrongMode: true });
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
  listArchetypes,
  creditEstimate,
  generate,
  regenerate,
  tweak,
  sendThreadMessage,
  listThreads,
  getThread,
  renameThread,
  moveThread,
  deleteThread,
  getGeneration,
  listGenerations,
  downloadGeneration,
  serializeThread,
  DOWNLOAD_FORMATS,
};
