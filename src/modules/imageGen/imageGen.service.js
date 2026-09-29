const { v4: uuidv4 } = require('uuid');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const { generateForModel, editForModel } = require('../../shared/services/ai');
const { getObjectBuffer, uploadFileToKey } = require('../s3/s3.service');
const { persistWorkspaceAsset } = require('../asset/asset.service');
const prisma = require('../../shared/config/prismaClient');
const projectDao = require('../project/project.dao');
const imageGenCredit = require('./imageGenCredit.service');
const imageGenDao = require('./imageGen.dao');
const threadDao = require('./imageGen.thread.dao');
const messageDao = require('./imageGen.message.dao');
const rateLimit = require('./imageGenRateLimit.service');
const contextService = require('./imageGen.context.service');
const {
  listModels,
  modelCatalog,
  resolveModel,
  estimateCredits,
  defaultModelIdForMode,
  modeAc,
} = require('./catalogs/models');
const {
  listFormats,
  resolveFormat,
  isFormatForMode,
  defaultFormatIdForMode,
  openaiSizeForFormat,
  geminiImageConfigForFormat,
  printInfo,
} = require('./catalogs/formats');
const { listStyles, resolveStyle } = require('./catalogs/styles');
const { listArchetypes } = require('./catalogs/archetypes');
const { buildImagePrompt } = require('./prompts/imageStyle.prompt');
const { buildChatEditInstruction } = require('./prompts/chatEdit.prompt');
const { cropToFormat, cropToPrint, padToAspect } = require('./socialCrop.service');
const { DOWNLOAD_FORMATS, sendDownload } = require('./imageGenExport.service');
const { resolveAssetFilename } = require('./imageGenFilename');
const { IMAGE_GEN_FEATURE } = require('../../shared/config/imageGenCreditPricing');
const infographicService = require('./infographic.service');
const socialService = require('./social.service');
const printService = require('./print.service');

const STUDIO_MODES = Object.freeze(['image', 'infographic', 'social', 'printable']);

function normalizeMode(value) {
  return STUDIO_MODES.includes(value) ? value : 'image';
}

function sameColors(a, b) {
  const left = Array.isArray(a) ? a : [];
  const right = Array.isArray(b) ? b : [];
  return left.length === right.length && left.every((c, i) => c === right[i]);
}

function styleChanged(body, prev) {
  if (body.style === undefined && body.styleId === undefined) return false;
  return (body.style || body.styleId) !== prev.styleId;
}

function shouldRebuildInfographicSpec(body = {}, prev = {}) {
  if (body.prompt !== undefined && body.prompt !== prev.prompt) return true;
  if (body.archetypeHint !== undefined && body.archetypeHint !== prev.archetypeHint) {
    return true;
  }
  if (body.styleHint !== undefined && body.styleHint !== prev.styleHint) return true;
  if (styleChanged(body, prev)) return true;
  if (body.contextId !== undefined && body.contextId !== prev.contextId) return true;
  return false;
}

/** Copy/look inputs rebuild a design spec; model-only changes re-render it. */
function shouldRebuildDesignSpec(body = {}, prev = {}) {
  if (body.prompt !== undefined && body.prompt !== prev.prompt) return true;
  if (body.styleHint !== undefined && body.styleHint !== prev.styleHint) return true;
  if (styleChanged(body, prev)) return true;
  if (body.brandPalette !== undefined && !sameColors(body.brandPalette, prev.brandPalette)) {
    return true;
  }
  if (body.contextId !== undefined && body.contextId !== prev.contextId) return true;
  return false;
}

function designSpecHandler({ service, requestKey, invalidMessage }) {
  return {
    service,
    requestKey,
    invalidMessage,
    fit: 'cover',
    lockFormat: true,
    shouldRebuild: shouldRebuildDesignSpec,
    build: ({ prompt, contextText, styleHint, brandPalette, format }) =>
      service.buildSpec({ prompt, contextText, styleHint, brandPalette, format }),
    normalize: (spec) => spec,
    render: ({ spec, format, sizing, hasReferences }) =>
      service.buildRenderPrompt({ spec, format, sizing, hasReferences }),
    pixelInstruction: ({ instruction, spec }) =>
      service.buildPixelEditInstruction({ instruction, spec }),
  };
}

/**
 * Spec-first modes: an LLM writes a spec from the prompt, the spec is rendered,
 * and chat edits either patch the spec or pixel-edit the image.
 */
const SPEC_HANDLERS = Object.freeze({
  infographic: {
    service: infographicService,
    requestKey: 'infographicSpec',
    invalidMessage: messages.IMAGE_GEN_SPEC_INVALID,
    fit: 'contain',
    lockFormat: false,
    shouldRebuild: shouldRebuildInfographicSpec,
    build: ({ prompt, contextText, styleHint, archetypeHint, format }) =>
      infographicService.buildSpec({
        prompt,
        contextText,
        archetypeHint: archetypeHint || null,
        styleHint,
        format,
      }),
    normalize: (spec, format) =>
      spec && !spec.orientation ? { ...spec, orientation: format.id } : spec,
    render: ({ spec, format, hasReferences }) =>
      infographicService.buildRenderPrompt({ spec, format, hasReferences }),
    pixelInstruction: ({ instruction }) => instruction,
  },
  social: designSpecHandler({
    service: socialService,
    requestKey: 'socialSpec',
    invalidMessage: messages.IMAGE_GEN_SOCIAL_SPEC_INVALID,
  }),
  printable: designSpecHandler({
    service: printService,
    requestKey: 'printSpec',
    invalidMessage: messages.IMAGE_GEN_PRINT_SPEC_INVALID,
  }),
});

const SPEC_MODES = Object.freeze(Object.keys(SPEC_HANDLERS));

function specHandlerFor(mode) {
  return SPEC_HANDLERS[mode] || null;
}

function printBleedKey(workspaceId, generationId) {
  return `workspace/${workspaceId}/image-gen/print-bleed/${generationId}.png`;
}

/**
 * Crop the provider output to the final canvas. Printables also store the bleed
 * master next to the trim-size asset and return its print metadata.
 */
async function finalizeOutput({ buffer, format, mode, workspaceId, generationId }) {
  if (mode === 'printable') {
    const { trim, bleed } = await cropToPrint(buffer, format);
    const bleedKey = printBleedKey(workspaceId, generationId);
    await uploadFileToKey(bleed.buffer, bleedKey, 'image/png');
    return {
      cropped: trim,
      print: { ...printInfo(format), bleedKey },
    };
  }
  const handler = specHandlerFor(mode);
  const cropped = await cropToFormat(buffer, format, { fit: handler ? handler.fit : 'cover' });
  return { cropped, print: null };
}

function publicPrintInfo(print) {
  if (!print) return null;
  const { bleedKey, ...rest } = print;
  return { ...rest, bleedAvailable: Boolean(bleedKey) };
}

function platformFor(formatId) {
  return resolveFormat(formatId)?.platform || null;
}

function serializeGeneration(row) {
  if (!row) return row;
  const request = row.request && typeof row.request === 'object' ? row.request : {};
  const infographicSpec = request.infographicSpec || null;
  const socialSpec = request.socialSpec || null;
  const printSpec = request.printSpec || null;
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
    socialSpec,
    printSpec,
    print: publicPrintInfo(request.print),
    platform: platformFor(row.formatId),
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
    formatId: generation.formatId || null,
    platform: platformFor(generation.formatId),
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
    platform: platformFor(row.formatId),
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

/**
 * Resolve the canvas for a mode. Social and printable have no default: a size is required.
 */
function resolveRequestFormat(formatId, mode = 'image') {
  const id = formatId || defaultFormatIdForMode(mode);
  if (!id) {
    throw new AppError(`formatId is required for ${mode} mode`, 400);
  }
  const format = resolveFormat(id);
  if (!format) {
    throw new AppError('Invalid formatId', 400);
  }
  if (!isFormatForMode(format, mode)) {
    throw new AppError(`formatId "${format.id}" is not available in ${mode} mode`, 400);
  }
  return format;
}

/**
 * Per-provider sizing. OpenAI takes a WxH string; Gemini takes an aspect ratio
 * plus a resolution tier, so we persist the target WxH for parity in the DB.
 */
function providerSizingFor(model, format) {
  if (model && model.provider === 'gemini') {
    const { aspectRatio, imageSize } = geminiImageConfigForFormat(format, model);
    const size = format ? `${format.width}x${format.height}` : '1024x1024';
    return {
      size,
      aspectRatio,
      imageSize: format && format.category === 'print' ? imageSize : undefined,
    };
  }
  return {
    size: openaiSizeForFormat(format, model && model.providerModel),
    aspectRatio: null,
    imageSize: undefined,
  };
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
  spec: providedSpec = null,
  specWarnings: providedWarnings = null,
  skipSpecBuild = false,
}) {
  const mode = normalizeMode(modeInput);
  const handler = specHandlerFor(mode);
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

  const format = resolveRequestFormat(formatId, mode);
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

  const sizing = providerSizingFor(model, format);

  let enrichedPrompt;
  let spec = providedSpec || null;
  let specWarnings = Array.isArray(providedWarnings) ? [...providedWarnings] : [];
  let renderPromptPreview = null;

  if (handler) {
    if (!skipSpecBuild || !spec) {
      const built = await handler.build({
        prompt: String(prompt).trim(),
        contextText: contextResult.enrichmentBlock || '',
        styleHint: infographicService.mergeStyleHint({ styleHint, style: styleId, styleId }),
        archetypeHint,
        brandPalette,
        format,
      });
      spec = built.spec;
      specWarnings = [...specWarnings, ...(built.warnings || [])];
    } else {
      spec = handler.normalize(spec, format);
    }

    enrichedPrompt = handler.render({ spec, format, sizing, hasReferences: useRefs });
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

  const { size: requestedSize, aspectRatio, imageSize } = sizing;
  const generated = await generateForModel({
    model,
    prompt: enrichedPrompt,
    size: requestedSize,
    aspectRatio,
    imageSize,
    referenceBuffers: useRefs ? referenceBuffers : [],
  });
  const openaiSize = requestedSize;

  const revisedPrompt = generated.revised_prompt || null;
  const generationId = uuidv4();
  const { cropped, print } = await finalizeOutput({
    buffer: generated.buffer,
    format,
    mode,
    workspaceId: workspace.id,
    generationId,
  });
  const archetype = mode === 'infographic' ? spec?.archetype || null : null;
  const assetName = resolveAssetFilename({
    name,
    prompt,
    mode,
  });

  const resolvedRootId = rootId || parentId || generationId;
  const liveContextId = contextResult.usedLiveContext ? contextResult.contextId : null;
  const chargeFeature = pricing.breakdown.feature || model.feature;
  const chargeAmount = pricing.athenaCredits;

  // CHARGE UPFRONT to prevent race condition exploit
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
      archetype,
      platform: format.platform || null,
      ...(print ? { print: { formatId: format.id, dpi: print.dpi } } : {}),
    },
  });

  const charged = charge?.pricing?.athenaCredits ?? chargeAmount;

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
      archetype,
      platform: format.platform || null,
      ...(print ? { dpi: print.dpi } : {}),
    },
  });

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
    ...(handler
      ? {
          [handler.requestKey]: spec,
          warnings: specWarnings,
          renderPromptPreview,
        }
      : {}),
    ...(print ? { print } : {}),
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
    creditsCharged: charged,
    status: 'SUCCEEDED',
  });

  if (contextResult.pinContextId) {
    await contextService.pinIfNeeded(contextResult.pinContextId);
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

  const mode = normalizeMode(parent.mode);
  const model = resolveModel(parent.modelId) || resolveModel(defaultModelIdForMode(mode));
  const format = parent.formatId
    ? resolveFormat(parent.formatId)
    : resolveRequestFormat(null, mode);
  const pricing = estimateCredits({
    modelId: model.id,
    mode,
    isTweak: true,
  });

  await rateLimit.assertRegenerateAllowed(userId, workspace.id);
  await imageGenCredit.assertAfford(workspace.id, userId, pricing.athenaCredits);

  const prev = parent.request || {};
  const handler = specHandlerFor(mode);
  const sizing = providerSizingFor(model, format);
  const { size: openaiSize, aspectRatio, imageSize } = sizing;
  const sourceKey = (mode === 'printable' && prev.print?.bleedKey) || parent.s3Key;
  let sourceBuffer = await getObjectBuffer(sourceKey);
  let editInstruction = String(editPrompt || instruction).trim();
  if (handler && handler.lockFormat) {
    sourceBuffer = await padToAspect(sourceBuffer, handler.service.providerAspectFor(sizing));
    editInstruction = handler.pixelInstruction({
      instruction: editInstruction,
      spec: prev[handler.requestKey] || null,
    });
  }
  const edited = await editForModel({
    model,
    imageBuffer: sourceBuffer,
    instruction: editInstruction,
    size: openaiSize,
    aspectRatio,
    imageSize,
  });

  const generationIdNew = uuidv4();
  const { cropped, print } = await finalizeOutput({
    buffer: edited.buffer,
    format,
    mode,
    workspaceId: workspace.id,
    generationId: generationIdNew,
  });
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
      platform: format?.platform || null,
      ...(print ? { dpi: print.dpi } : {}),
    },
  });

  const chargeFeature = pricing.breakdown.feature || IMAGE_GEN_FEATURE.TWEAK;
  const chargeAmount = modeAc(mode, model.id);

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
    ...(handler
      ? {
          [handler.requestKey]: prev[handler.requestKey] || null,
          ...(handler.lockFormat ? { styleHint: prev.styleHint || null } : {}),
          pixelEdited: true,
          warnings: prev.warnings || [],
        }
      : {}),
    ...(print ? { print } : {}),
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
      pixelEdited: SPEC_MODES.includes(mode),
      ...(print ? { print: { formatId: format.id, dpi: print.dpi } } : {}),
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
  if (body.mode && !STUDIO_MODES.includes(body.mode)) {
    throw new AppError(messages.IMAGE_GEN_MODE_INVALID, 400);
  }
  const mode = normalizeMode(body.mode);
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
    formatId: body.formatId || null,
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

async function regenerate({ userId, workspace, generationId, body = {} }) {
  const parent = requireStudioGeneration(
    await imageGenDao.findById(generationId, workspace.id)
  );

  const prev = parent.request || {};
  const mode = normalizeMode(parent.mode);
  const handler = specHandlerFor(mode);

  if (body.mode && body.mode !== parent.mode) {
    throw new AppError(messages.IMAGE_GEN_MODE_MISMATCH, 400);
  }
  if (
    handler &&
    handler.lockFormat &&
    body.formatId &&
    body.formatId !== (parent.formatId || prev.formatId)
  ) {
    throw new AppError(messages.IMAGE_GEN_FORMAT_LOCKED, 400);
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

  const prevSpec = handler ? prev[handler.requestKey] || null : null;
  const reuseSpec = Boolean(handler && prevSpec && !handler.shouldRebuild(body, prev));

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
      body.formatId !== undefined && body.formatId !== null && body.formatId !== ''
        ? body.formatId
        : parent.formatId || prev.formatId || null,
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
    spec: reuseSpec ? prevSpec : null,
    specWarnings: reuseSpec ? prev.warnings || null : null,
    skipSpecBuild: reuseSpec,
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

async function runSpecPatchEdit({ userId, workspace, parent, instruction, threadId }) {
  const mode = normalizeMode(parent.mode);
  const handler = specHandlerFor(mode);
  const prev = parent.request || {};
  const existingSpec = prev[handler.requestKey];
  if (!existingSpec) {
    throw new AppError(handler.invalidMessage, 400);
  }

  const format = resolveRequestFormat(parent.formatId || prev.formatId, mode);
  const patched = await handler.service.patchSpec({
    spec: existingSpec,
    instruction,
    format,
  });

  return runPipeline({
    userId,
    workspace,
    mode,
    modelId: parent.modelId || defaultModelIdForMode(mode),
    formatId: format.id,
    styleId: parent.styleId || prev.styleId,
    styleHint: prev.styleHint || null,
    archetypeHint:
      mode === 'infographic' ? patched.spec.archetype || prev.archetypeHint : null,
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
    spec: patched.spec,
    specWarnings: patched.warnings,
    skipSpecBuild: true,
  });
}

/**
 * Spec-first modes: patch the spec and re-render, or pixel-edit.
 * Returns null for image mode so callers keep their own edit composition.
 */
async function runSpecModeEdit({ userId, workspace, parent, instruction, editMode, threadId }) {
  const handler = specHandlerFor(parent.mode);
  if (!handler) return null;

  const route = await handler.service.classifyEdit({ instruction, editMode });
  if (route === 'spec') {
    return runSpecPatchEdit({ userId, workspace, parent, instruction, threadId });
  }
  return runTweakOnParent({
    userId,
    workspace,
    parent,
    instruction,
    editPrompt: instruction,
    threadId,
  });
}

async function tweak({ userId, workspace, generationId, instruction, editMode = null }) {
  const parent = requireStudioGeneration(
    await imageGenDao.findById(generationId, workspace.id)
  );
  const thread = await ensureThreadForParent({ parent, workspace, userId });

  let result = await runSpecModeEdit({
    userId,
    workspace,
    parent,
    instruction,
    editMode,
    threadId: thread.id,
  });
  if (!result) {
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
  let result = await runSpecModeEdit({
    userId,
    workspace,
    parent,
    instruction: String(content).trim(),
    editMode,
    threadId: thread.id,
  });
  if (!result) {
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
  const modeFilter = STUDIO_MODES.includes(query.mode) ? query.mode : undefined;
  const rows = await imageGenDao.listGenerations({
    workspaceId: workspace.id,
    userId,
    isPrivate: workspace.type === 'PRIVATE',
    take: query.take,
    skip: query.skip,
    mode: modeFilter,
    threadId: query.threadId,
  });
  // When mode omitted, return every studio mode (filter out any legacy unknown modes)
  const filtered = modeFilter
    ? rows
    : rows.filter((row) => STUDIO_MODES.includes(row.mode));
  return filtered.map(serializeGeneration);
}

function creditEstimate({ modelId, mode, tweak }) {
  if (mode && !STUDIO_MODES.includes(mode)) {
    throw new AppError(messages.IMAGE_GEN_MODE_INVALID, 400);
  }
  const resolvedMode = normalizeMode(mode);
  return estimateCredits({
    modelId,
    mode: resolvedMode,
    isTweak: tweak === true || tweak === 'true',
  });
}

async function downloadGeneration({ req, res, workspace, generationId, format, bleed = false }) {
  const row = await imageGenDao.findById(generationId, workspace.id);
  requireStudioGeneration(row, { notFoundIfWrongMode: true });
  const filenameBase = row.asset?.name || `image-${row.id}`;
  return sendDownload(req, res, {
    s3Key: row.s3Key,
    format,
    filenameBase,
    generation: row,
    bleed,
  });
}

/**
 * Fetch a generation safely without workspace context for public sharing
 */
async function getSharedGeneration(token) {
  // Token is just the generationId UUID
  const row = await imageGenDao.findGlobalById(token);
  if (!row) {
    throw new AppError('Shared generation not found or is no longer available.', 404);
  }

  const creatorName = (row.user && row.user.name) ? row.user.name : 'Unknown';

  return {
    id: row.id,
    prompt: row.prompt,
    mode: row.mode,
    url: row.asset?.url,
    createdAt: row.createdAt,
    version: row.version,
    creatorName
  };
}
module.exports = {
  listModels,
  modelCatalog,
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
  getSharedGeneration,
  listGenerations,
  downloadGeneration,
  serializeThread,
  DOWNLOAD_FORMATS,
};
