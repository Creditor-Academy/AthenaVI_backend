const fs = require('fs/promises');
const os = require('os');
const path = require('path');

const { bundle } = require('@remotion/bundler');
const { renderMedia, selectComposition } = require('@remotion/renderer');

const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const projectDao = require('../project/project.dao');
const renderDao = require('./render.dao');
const heygenService = require('../video/services/heygen.service');
const { getPresignedGetUrl, uploadFileToKey } = require('../s3/s3.service');
const { createSceneHash } = require('./cache/sceneHash');
const {
  buildProjectRenderFinalKey,
  buildProjectSceneCacheKey,
} = require('../../shared/utils/videoStorageKeys');
const { DEFAULT_VIDEO_SETTINGS } = require('../../shared/constants/videoEditor');
const { buildSceneTimings } = require('./remotion/transitions');
const { collectAssetIds, extractAssetId } = require('../../shared/utils/projectAssetIds');
const projectStorageService = require('../project/projectStorage.service');
const creditLedger = require('../credit/creditLedger.service');
const prisma = require('../../shared/config/prismaClient');
const {
  FEATURE,
  SCOPE,
  calculateUsageCredits,
  estimateDurationFromFrames,
} = require('../../shared/config/creditPricing');
const { getEffectiveHeygenFields, isHeygenAvatarElement } = require('../project/projectEditorNormalize');

const PRESIGN_TTL_SECONDS = 3600;
let remotionBundlePromise = null;

async function getProjectOrThrow(workspaceId, projectId) {
  const project = await projectDao.findProjectById(workspaceId, projectId);
  if (!project) {
    throw new AppError(messages.PROJECT_NOT_FOUND, 404);
  }
  return project;
}

function getProjectData(project) {
  const data = project.data || {};
  return {
    ...data,
    videoSettings: {
      ...DEFAULT_VIDEO_SETTINGS,
      ...(data.videoSettings || {}),
    },
    scenes: Array.isArray(data.scenes) ? data.scenes : [],
  };
}

async function buildAssetLookup(workspaceId, projectData) {
  const assetIds = collectAssetIds(projectData);
  const assets = await projectDao.findAssetsByIds(workspaceId, assetIds);
  const map = new Map(assets.map((asset) => [asset.id, asset]));

  for (const assetId of assetIds) {
    if (!map.has(assetId)) {
      throw new AppError(messages.ASSET_NOT_FOUND, 404);
    }
  }

  return map;
}

async function resolveAssetSource(asset) {
  return {
    assetId: asset.id,
    assetKey: asset.key,
    src: await getPresignedGetUrl(asset.key, PRESIGN_TTL_SECONDS),
    mimeType: asset.type,
    name: asset.name,
  };
}

async function resolveBackground(background, assetLookup) {
  if (!background || background.type === 'color') {
    return background || { type: 'color', value: '#000000' };
  }

  const assetId = extractAssetId(background);
  if (!assetId) {
    if (typeof background.value === 'string') {
      return {
        ...background,
        src: background.value,
      };
    }
    return background;
  }

  const asset = assetLookup.get(assetId);
  if (!asset) {
    throw new AppError(messages.ASSET_NOT_FOUND, 404);
  }

  return {
    ...background,
    ...(await resolveAssetSource(asset)),
  };
}

async function resolveElementContent({ workspaceId, projectId, scene, element, assetLookup }) {
  const content = { ...(element.content || {}) };

  if (isHeygenAvatarElement(element)) {
    const { heygenVideoId } = getEffectiveHeygenFields(scene, content);
    if (!heygenVideoId) {
      throw new AppError(messages.PROJECT_SCENE_ASSET_NOT_READY, 409);
    }

    const heygenRow = await heygenService.assertHeygenVideoReadyInS3(
      workspaceId,
      projectId,
      heygenVideoId
    );

    return {
      ...content,
      heygenVideoId,
      src: await getPresignedGetUrl(heygenRow.s3Key, PRESIGN_TTL_SECONDS),
      assetKey: heygenRow.s3Key,
    };
  }

  const assetId = extractAssetId(content);
  if (assetId) {
    const asset = assetLookup.get(assetId);
    if (!asset) {
      throw new AppError(messages.ASSET_NOT_FOUND, 404);
    }

    return {
      ...content,
      ...(await resolveAssetSource(asset)),
    };
  }

  if (content.fill && typeof content.fill === 'object') {
    const fillAssetId = extractAssetId(content.fill);
    if (fillAssetId) {
      const asset = assetLookup.get(fillAssetId);
      if (!asset) {
        throw new AppError(messages.ASSET_NOT_FOUND, 404);
      }

      return {
        ...content,
        fill: {
          ...content.fill,
          ...(await resolveAssetSource(asset)),
        },
      };
    }
  }

  return content;
}

async function buildSceneManifest({ workspaceId, projectId, scene, assetLookup }) {
  const resolvedElements = [];
  for (const element of scene.elements || []) {
    resolvedElements.push({
      ...element,
      content: await resolveElementContent({
        workspaceId,
        projectId,
        scene,
        element,
        assetLookup,
      }),
    });
  }

  return {
    ...scene,
    background: await resolveBackground(scene.background, assetLookup),
    elements: resolvedElements,
  };
}

async function resolveProjectManifest(project) {
  const data = getProjectData(project);
  if (!data.scenes.length) {
    throw new AppError(messages.PROJECT_SCENES_REQUIRED, 400);
  }

  const assetLookup = await buildAssetLookup(project.workspaceId, data);
  const scenes = [];

  for (const scene of data.scenes) {
    const manifest = await buildSceneManifest({
      workspaceId: project.workspaceId,
      projectId: project.id,
      scene,
      assetLookup,
    });
    const sceneHash = createSceneHash({
      videoSettings: data.videoSettings,
      scene: manifest,
    });

    scenes.push({
      ...manifest,
      sceneHash,
    });
  }

  return {
    videoSettings: data.videoSettings,
    scenes,
  };
}

async function ensureRemotionBundle() {
  if (!remotionBundlePromise) {
    const entryPoint = path.join(__dirname, 'remotion', 'entry.jsx');
    remotionBundlePromise = bundle({
      entryPoint,
      onProgress: () => undefined,
    });
  }

  return remotionBundlePromise;
}

async function renderCompositionToFile({ serveUrl, id, inputProps, outputLocation }) {
  const composition = await selectComposition({
    serveUrl,
    id,
    inputProps,
  });

  await renderMedia({
    serveUrl,
    composition,
    codec: 'h264',
    outputLocation,
    inputProps,
  });
}

async function ensureTempDirectory(renderId) {
  const directory = path.join(os.tmpdir(), 'athena-video-renders', renderId);
  await fs.mkdir(directory, { recursive: true });
  return directory;
}

async function renderSceneCaches({
  project,
  manifest,
  forceRebuild,
  renderId,
  serveUrl,
}) {
  const tempDirectory = await ensureTempDirectory(renderId);
  const sceneCacheEntries = [];

  for (let index = 0; index < manifest.scenes.length; index += 1) {
    const scene = manifest.scenes[index];
    const cached = forceRebuild
      ? null
      : await renderDao.findSceneRenderCache(project.id, scene.sceneId, scene.sceneHash);

    if (cached?.s3Key) {
      sceneCacheEntries.push({
        sceneId: scene.sceneId,
        durationInFrames: scene.durationInFrames,
        transition: scene.transition,
        src: await getPresignedGetUrl(cached.s3Key, PRESIGN_TTL_SECONDS),
        cacheId: cached.id,
        sceneHash: scene.sceneHash,
        s3Key: cached.s3Key,
      });
      continue;
    }

    const outputLocation = path.join(tempDirectory, `${scene.sceneId}-${scene.sceneHash}.mp4`);
    await renderCompositionToFile({
      serveUrl,
      id: 'SceneComposition',
      inputProps: {
        scene,
        videoSettings: manifest.videoSettings,
      },
      outputLocation,
    });

    const fileBuffer = await fs.readFile(outputLocation);
    const s3Key = buildProjectSceneCacheKey({
      workspaceId: project.workspaceId,
      folderId: project.folderId,
      projectId: project.id,
      sceneId: scene.sceneId,
      sceneHash: scene.sceneHash,
    });

    const uploaded = await uploadFileToKey(fileBuffer, s3Key, 'video/mp4');
    const cacheRow = await renderDao.upsertSceneRenderCache({
      workspaceId: project.workspaceId,
      folderId: project.folderId,
      projectId: project.id,
      sceneId: scene.sceneId,
      sceneHash: scene.sceneHash,
      s3Key: uploaded.key,
      outputUrl: uploaded.url,
      fileSizeBytes: fileBuffer.length,
      metadata: {
        durationInFrames: scene.durationInFrames,
        transition: scene.transition || null,
      },
    });
    await projectStorageService.recalculateProjectStorage(project.id);

    sceneCacheEntries.push({
      sceneId: scene.sceneId,
      durationInFrames: scene.durationInFrames,
      transition: scene.transition,
      src: await getPresignedGetUrl(uploaded.key, PRESIGN_TTL_SECONDS),
      cacheId: cacheRow.id,
      sceneHash: scene.sceneHash,
      s3Key: uploaded.key,
    });
  }

  return sceneCacheEntries;
}

async function chargeRenderIfNeeded({ renderId, workspaceId, userId, durationInFrames, fps }) {
  const render = await renderDao.findProjectRenderByIdOnly(renderId);
  if (!render || render.billingStatus === 'charged' || render.billingStatus === 'skipped') {
    return;
  }
  if (!userId) {
    await renderDao.updateProjectRender(renderId, { billingStatus: 'skipped' });
    return;
  }

  const durationSeconds = estimateDurationFromFrames(durationInFrames, fps);
  const pricing = calculateUsageCredits({
    feature: FEATURE.REMOTION_EXPORT,
    durationSeconds,
  });

  let projectName = null;
  if (render.projectId) {
    const project = await prisma.project.findUnique({
      where: { id: render.projectId },
      select: { id: true, name: true },
    });
    projectName = project?.name || null;
  }

  await creditLedger.chargeUsage({
    scope: SCOPE.WORKSPACE,
    workspaceId,
    userId,
    amountAc: pricing.athenaCredits,
    idempotencyKey: `project-render:${renderId}`,
    reference: renderId,
    metadata: {
      feature: FEATURE.REMOTION_EXPORT,
      renderId,
      projectId: render.projectId,
      projectName,
      videoName: projectName,
      durationSeconds,
      durationInFrames,
      fps,
      heygenUsdCost: pricing.heygenUsdCost,
      scope: SCOPE.WORKSPACE,
    },
  });

  await renderDao.updateProjectRender(renderId, {
    billingStatus: 'charged',
    creditsCharged: pricing.athenaCredits,
    billedDurationSec: durationSeconds,
  });
}

async function processProjectRender({ renderId, workspaceId, projectId, userId, forceRebuild }) {
  const tempDirectory = await ensureTempDirectory(renderId);

  try {
    const project = await getProjectOrThrow(workspaceId, projectId);
    const manifest = await resolveProjectManifest(project);

    await renderDao.updateProjectRender(renderId, {
      status: 'processing',
      progress: 5,
      startedAt: new Date(),
      inputSnapshot: project.data,
      sceneHashes: manifest.scenes.map((scene) => ({
        sceneId: scene.sceneId,
        sceneHash: scene.sceneHash,
      })),
    });

    const serveUrl = await ensureRemotionBundle();
    const cachedScenes = await renderSceneCaches({
      project,
      manifest,
      forceRebuild,
      renderId,
      serveUrl,
    });

    await renderDao.updateProjectRender(renderId, {
      progress: 70,
    });

    const outputLocation = path.join(tempDirectory, 'final.mp4');
    await renderCompositionToFile({
      serveUrl,
      id: 'ProjectRenderComposition',
      inputProps: {
        videoSettings: manifest.videoSettings,
        scenes: cachedScenes,
      },
      outputLocation,
    });

    const finalBuffer = await fs.readFile(outputLocation);
    const s3Key = buildProjectRenderFinalKey({
      workspaceId,
      folderId: project.folderId,
      projectId,
      renderId,
    });
    const uploaded = await uploadFileToKey(finalBuffer, s3Key, 'video/mp4');
    const totalDuration = buildSceneTimings(cachedScenes).durationInFrames;
    const fps = manifest.videoSettings?.fps || 30;

    await renderDao.updateProjectRender(renderId, {
      status: 'completed',
      progress: 100,
      s3Key: uploaded.key,
      outputUrl: uploaded.url,
      fileSizeBytes: finalBuffer.length,
      completedAt: new Date(),
      error: null,
    });
    await chargeRenderIfNeeded({
      renderId,
      workspaceId,
      userId,
      durationInFrames: totalDuration,
      fps,
    });
    await projectDao.updateProject(projectId, {
      status: 'completed',
      duration: totalDuration,
    });
    await projectStorageService.recalculateProjectStorage(projectId);
  } catch (error) {
    await renderDao.updateProjectRender(renderId, {
      status: 'failed',
      billingStatus: 'failed',
      progress: 100,
      failedAt: new Date(),
      error: error.message,
    });

    try {
      await projectDao.updateProject(projectId, {
        status: 'failed',
      });
    } catch (projectUpdateError) {
      void projectUpdateError;
    }
  } finally {
    await fs.rm(tempDirectory, { recursive: true, force: true });
  }
}

const startProjectRender = async ({ workspaceId, projectId, userId, forceRebuild }) => {
  const project = await getProjectOrThrow(workspaceId, projectId);
  const projectData = getProjectData(project);

  if (!projectData.scenes.length) {
    throw new AppError(messages.PROJECT_SCENES_REQUIRED, 400);
  }

  const timeline = buildSceneTimings(projectData.scenes);
  const fps = projectData.videoSettings?.fps || 30;
  const estimate = calculateUsageCredits({
    feature: FEATURE.REMOTION_EXPORT,
    durationSeconds: estimateDurationFromFrames(timeline.durationInFrames, fps),
  });
  await creditLedger.assertCanAfford({
    scope: SCOPE.WORKSPACE,
    workspaceId,
    userId,
    estimatedAc: estimate.athenaCredits,
  });

  const render = await renderDao.createProjectRender({
    workspaceId,
    folderId: project.folderId,
    projectId,
    triggeredBy: userId,
    status: 'queued',
    progress: 0,
    inputSnapshot: project.data,
  });

  await projectDao.updateProject(projectId, {
    status: 'rendering',
  });

  setImmediate(() => {
    processProjectRender({
      renderId: render.id,
      workspaceId,
      projectId,
      userId,
      forceRebuild,
    }).catch(async (error) => {
      try {
        await renderDao.updateProjectRender(render.id, {
          status: 'failed',
          progress: 100,
          failedAt: new Date(),
          error: error.message,
        });
      } catch (updateError) {
        void updateError;
      }
    });
  });

  return render;
};

const listProjectRenders = async (workspaceId, projectId) => {
  await getProjectOrThrow(workspaceId, projectId);
  return renderDao.listProjectRenders(workspaceId, projectId);
};

const getProjectRender = async (workspaceId, projectId, renderId) => {
  await getProjectOrThrow(workspaceId, projectId);
  const render = await renderDao.findProjectRenderById(workspaceId, projectId, renderId);
  if (!render) {
    throw new AppError(messages.PROJECT_RENDER_NOT_FOUND, 404);
  }
  return render;
};

const getRenderDownloadUrl = async (workspaceId, projectId, renderId) => {
  const render = await getProjectRender(workspaceId, projectId, renderId);
  if (render.status !== 'completed' || !render.s3Key) {
    throw new AppError(messages.PROJECT_RENDER_NOT_READY, 409);
  }

  return {
    presignedUrl: await getPresignedGetUrl(render.s3Key, PRESIGN_TTL_SECONDS),
    expiresInSeconds: PRESIGN_TTL_SECONDS,
    render,
  };
};

module.exports = {
  startProjectRender,
  listProjectRenders,
  getProjectRender,
  getRenderDownloadUrl,
  resolveProjectManifest,
};
