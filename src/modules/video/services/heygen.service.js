const prisma = require('../../../shared/config/prismaClient');
const heygenDao = require('../heygen.dao');
const heygenV3Service = require('../../heygen/heygenV3.service');
const { generateHeygenRequestHash } = require('../../../shared/utils/requestHash');
const { uploadFileToKey, getPresignedGetUrl } = require('../../s3/s3.service');
const AppError = require('../../../shared/utils/AppError');
const messages = require('../../../shared/utils/messages');
const { toJsonNumber } = require('../../../shared/utils/byteSize');
const { buildHeygenSceneVideoKey } = require('../../../shared/utils/videoStorageKeys');
const {
  normalizeHeygenOutputFormat,
  heygenOutputContentType,
  resolveHeygenOutputFormatFromRecord,
} = require('../../../shared/utils/heygenVideoFormat');
const projectStorageService = require('../../project/projectStorage.service');
const {
  HEYGEN_AVATAR_ENGINES,
  normalizeHeygenAvatarEngine,
  usesHeygenLegacyV2VideoApi,
  usesHeygenLegacyV2VideoLook,
  buildHeygenVideoEnginePayload,
  extractSupportedApiEnginesFromLook,
  resolveVideoPlanForLook,
  isStudioOrDigitalTwinAvatarType,
} = require('../../../shared/constants/heygen');
const creditLedger = require('../../credit/creditLedger.service');
const heygenAccess = require('../../heygen/heygenAccess.service');
const {
  truncateText,
  resolveSceneNameFromProjectData,
} = require('../../credit/creditHistory.enrich');
const {
  FEATURE,
  SCOPE,
  calculateUsageCredits,
  estimateDurationFromScript,
} = require('../../../shared/config/creditPricing');
const storageAccounting = require('../../storage/storageAccounting.service');

const POLL_INTERVAL_MS = 1500;
const MAX_POLL_ATTEMPTS = 24;
const PRESIGN_DEFAULT_TTL = 300;

/** In-flight S3 copies keyed by heygen_responses.id */
const s3UploadInflight = new Map();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isTerminalHeygenStatus(status) {
  const s = String(status || '').toLowerCase();
  return s === 'completed' || s === 'failed';
}

async function getProjectInWorkspace(workspaceId, projectId) {
  const project = await prisma.project.findFirst({
    where: { id: projectId, workspaceId },
    select: { id: true, folderId: true },
  });
  if (!project) {
    throw new AppError(messages.NOT_FOUND, 404);
  }
  return project;
}

/** Avatar IV + photo_avatar only; Avatar V rejects expressiveness on HeyGen. */
function shouldIncludeExpressiveness(avatarEngine, avatarType, expressiveness) {
  if (normalizeHeygenAvatarEngine(avatarEngine) !== HEYGEN_AVATAR_ENGINES.IV) {
    return false;
  }
  if (expressiveness == null || String(expressiveness).trim() === '') {
    return false;
  }
  const type = avatarType != null ? String(avatarType).trim() : '';
  return type === 'photo_avatar';
}

function buildHeyGenVideoPayload(body) {
  const {
    avatarId,
    avatarEngine,
    avatarType,
    title,
    resolution,
    aspectRatio,
    backgroundColor,
    voiceId,
    script,
    expressiveness,
    voiceSettings,
    removeBackground,
    outputFormat,
  } = body;

  const voice_settings = {
    speed: voiceSettings?.speed ?? 1,
    pitch: voiceSettings?.pitch ?? 0,
    ...(voiceSettings?.volume != null && { volume: voiceSettings.volume }),
    ...(voiceSettings?.locale && { locale: voiceSettings.locale }),
    ...(voiceSettings?.engine_settings && {
      engine_settings: voiceSettings.engine_settings,
    }),
  };

  const engine = normalizeHeygenAvatarEngine(avatarEngine);
  const format = normalizeHeygenOutputFormat(outputFormat);

  const payload = {
    type: 'avatar',
    avatar_id: avatarId,
    engine: buildHeygenVideoEnginePayload(engine),
    title,
    resolution,
    aspect_ratio: aspectRatio,
    output_format: format,
    script,
    voice_id: voiceId,
    voice_settings,
  };

  // HeyGen rejects `background` for webm and applies matting automatically.
  if (format === 'mp4') {
    payload.background = {
      type: 'color',
      value: backgroundColor,
    };
    payload.remove_background = removeBackground ?? false;
  }

  if (shouldIncludeExpressiveness(engine, avatarType, expressiveness)) {
    payload.expressiveness = expressiveness;
  }

  return payload;
}

function buildHeyGenV2Dimension(resolution, aspectRatio) {
  const isPortrait = aspectRatio === '9:16';
  const is720 = resolution === '720p';
  if (isPortrait) {
    return is720 ? { width: 720, height: 1280 } : { width: 1080, height: 1920 };
  }
  return is720 ? { width: 1280, height: 720 } : { width: 1920, height: 1080 };
}

/** HeyGen legacy POST /v2/video/generate — required for expressive public studio looks. */
function buildHeyGenV2VideoPayload(body) {
  const {
    avatarId,
    title,
    resolution,
    aspectRatio,
    backgroundColor,
    voiceId,
    script,
    voiceSettings,
  } = body;

  const voice = {
    type: 'text',
    input_text: script,
    voice_id: voiceId,
  };
  if (voiceSettings?.speed != null) voice.speed = voiceSettings.speed;
  if (voiceSettings?.pitch != null) voice.pitch = voiceSettings.pitch;

  return {
    video_inputs: [
      {
        character: {
          type: 'avatar',
          avatar_id: avatarId,
          avatar_style: 'normal',
        },
        voice,
        background: {
          type: 'color',
          value: backgroundColor,
        },
      },
    ],
    dimension: buildHeyGenV2Dimension(resolution, aspectRatio),
    ...(title ? { title } : {}),
    caption: false,
  };
}

async function resolveVideoEngineForAvatar(avatarId, avatarEngine, avatarType) {
  try {
    const lookBody = await heygenV3Service.getAvatarLook(avatarId);
    const plan = resolveVideoPlanForLook(lookBody, avatarEngine, avatarType);
    if (plan.videoApi === 'v2') {
      return { engine: HEYGEN_AVATAR_ENGINES.IV, useLegacyV2: true, plan };
    }
    if (plan.engine == null) {
      throw new AppError(messages.HEYGEN_AVATAR_ENGINE_UNSUPPORTED, 400);
    }
    return { engine: plan.engine, useLegacyV2: false, plan };
  } catch (err) {
    if (err instanceof AppError) throw err;
    const requested = normalizeHeygenAvatarEngine(avatarEngine);
    const useLegacyV2 = usesHeygenLegacyV2VideoApi(avatarId);
    // Preserve requested engine; studio/digital-twin still prefer Avatar V when look fetch fails.
    let engine = requested;
    if (!useLegacyV2 && isStudioOrDigitalTwinAvatarType(avatarType)) {
      engine = HEYGEN_AVATAR_ENGINES.V;
    }
    return {
      engine,
      useLegacyV2,
      plan: null,
    };
  }
}

async function createHeygenVideoJob(payloadBody, { useLegacyV2 }) {
  if (useLegacyV2) {
    const jsonBody = buildHeyGenV2VideoPayload(payloadBody);
    return heygenV3Service.createVideoV2(jsonBody);
  }
  const jsonBody = buildHeyGenVideoPayload(payloadBody);
  return heygenV3Service.createVideo(jsonBody);
}

/**
 * Start HeyGen avatar video generation; idempotent per request hash (includes sceneId).
 */
async function chargeHeygenVideoIfNeeded(record, remote, avatarEngine) {
  if (record.billingStatus === 'charged' || record.billingStatus === 'skipped') {
    return record;
  }
  if (!record.triggeredByUserId) {
    return heygenDao.updateHeygenResponse(record.id, { billingStatus: 'skipped' });
  }

  const durationSeconds =
    remote.duration != null && Number(remote.duration) > 0
      ? Number(remote.duration)
      : estimateDurationFromScript(
          record.billingContext?.script || record.billingContext?.scriptText
        );

  const billingContext =
    record.billingContext && typeof record.billingContext === 'object'
      ? record.billingContext
      : {};

  const pricing = calculateUsageCredits({
    feature: FEATURE.HEYGEN_VIDEO,
    durationSeconds,
    avatarEngine: avatarEngine || billingContext.avatarEngine,
    avatarType: billingContext.avatarType,
    resolution: billingContext.resolution,
  });
  let projectName = billingContext.projectName || null;
  let sceneName = billingContext.sceneName || null;
  if (record.projectId && (!projectName || !sceneName)) {
    const project = await prisma.project.findUnique({
      where: { id: record.projectId },
      select: { name: true, data: true },
    });
    if (!projectName) projectName = project?.name || null;
    if (!sceneName) {
      sceneName = resolveSceneNameFromProjectData(project?.data, record.sceneId);
    }
  }

  await creditLedger.chargeUsage({
    scope: SCOPE.WORKSPACE,
    workspaceId: record.workspaceId,
    userId: record.triggeredByUserId,
    amountAc: pricing.athenaCredits,
    idempotencyKey: `heygen-video:${record.id}`,
    metadata: {
      feature: FEATURE.HEYGEN_VIDEO,
      heygenVideoId: record.id,
      heygenJobId: record.videoId,
      projectId: record.projectId,
      projectName,
      sceneId: record.sceneId || null,
      sceneName,
      videoTitle: billingContext.title || null,
      scriptPreview: truncateText(billingContext.script || billingContext.scriptText),
      avatarEngine: avatarEngine || billingContext.avatarEngine || null,
      avatarType: billingContext.avatarType || null,
      resolution: billingContext.resolution || null,
      durationSeconds,
      heygenUsdCost: pricing.heygenUsdCost,
      scope: SCOPE.WORKSPACE,
    },
    reference: record.id,
  });

  return heygenDao.updateHeygenResponse(record.id, {
    billingStatus: 'charged',
    creditsCharged: pricing.athenaCredits,
    billedDurationSec: durationSeconds,
  });
}

const generateAvatarVideo = async (input) => {
  const {
    userId,
    workspaceId,
    projectId,
    sceneId,
    avatarId,
    avatarEngine,
    avatarType,
    title,
    resolution,
    aspectRatio,
    backgroundColor,
    voiceId,
    script,
    expressiveness,
    voiceSettings,
    removeBackground,
    outputFormat,
  } = input;

  const project = await getProjectInWorkspace(workspaceId, projectId);
  const sceneName = resolveSceneNameFromProjectData(project.data, sceneId);
  const normalizedOutputFormat = normalizeHeygenOutputFormat(outputFormat);
  const { engine, useLegacyV2, plan } = await resolveVideoEngineForAvatar(
    avatarId,
    avatarEngine,
    avatarType
  );
  const hashEngine = useLegacyV2 ? 'legacy_v2' : engine;

  if (normalizedOutputFormat === 'webm' && useLegacyV2) {
    throw new AppError(messages.HEYGEN_WEBM_NOT_SUPPORTED_FOR_LOOK, 400);
  }

  const requestHash = generateHeygenRequestHash({
    workspaceId,
    projectId,
    sceneId,
    avatarId,
    voiceId,
    script,
    avatarEngine: hashEngine,
    outputFormat: normalizedOutputFormat,
  });

  const existingResponse = await heygenDao.findHeygenResponseByRequestHash(requestHash);
  if (existingResponse) {
    return existingResponse;
  }

  const estimatedDuration = estimateDurationFromScript(script);
  const estimate = calculateUsageCredits({
    feature: FEATURE.HEYGEN_VIDEO,
    durationSeconds: estimatedDuration,
    avatarEngine: engine,
    avatarType,
    resolution,
  });
  await creditLedger.assertCanAfford({
    scope: SCOPE.WORKSPACE,
    workspaceId,
    userId,
    estimatedAc: estimate.athenaCredits,
  });

  await heygenAccess.assertCanUseAvatarLook({ userId, workspaceId, avatarId });
  await heygenAccess.assertCanUseVoice({ userId, workspaceId, voiceId });

  const payloadBody = {
    avatarId,
    avatarEngine: engine,
    avatarType,
    title,
    resolution,
    aspectRatio,
    backgroundColor,
    voiceId,
    script,
    expressiveness,
    voiceSettings,
    removeBackground,
    outputFormat: normalizedOutputFormat,
  };

  try {
    const created = await createHeygenVideoJob(payloadBody, { useLegacyV2 });
    return heygenDao.saveHeygenResponse({
      workspaceId,
      folderId: project.folderId,
      projectId,
      sceneId,
      videoId: created.videoId,
      videoUrl: '',
      s3Key: null,
      requestHash,
      status: created.status,
      rawResponse: created.raw,
    triggeredByUserId: userId,
    billingContext: {
      avatarEngine: useLegacyV2 ? 'legacy_v2' : engine,
      heygenApiVersion: created.apiVersion || (useLegacyV2 ? 'v2' : 'v3'),
      avatarType: avatarType || null,
      resolution: resolution || null,
      script,
      title: title || null,
      projectName: project.name,
      sceneName,
      estimatedCredits: estimate.athenaCredits,
      outputFormat: normalizedOutputFormat,
    },
    });
  } catch (err) {
    const msg = String(err?.message || '');
    if (!(err instanceof AppError) || err.statusCode !== 400 || useLegacyV2) {
      throw err;
    }

    const supported = plan?.supportedApiEngines || [];
    const supportsIv = supported.includes(HEYGEN_AVATAR_ENGINES.IV);
    const supportsV = supported.includes(HEYGEN_AVATAR_ENGINES.V);
    let fallbackEngine = null;

    // Never invent IV fallback for studio/digital-twin — HeyGen rejects Avatar IV for those.
    if (
      engine === HEYGEN_AVATAR_ENGINES.V &&
      /avatar v/i.test(msg) &&
      supportsIv &&
      !isStudioOrDigitalTwinAvatarType(avatarType)
    ) {
      fallbackEngine = HEYGEN_AVATAR_ENGINES.IV;
    } else if (
      engine === HEYGEN_AVATAR_ENGINES.IV &&
      /avatar iv/i.test(msg) &&
      (supportsV || isStudioOrDigitalTwinAvatarType(avatarType))
    ) {
      fallbackEngine = HEYGEN_AVATAR_ENGINES.V;
    }

    // Avatar III / unknown-engine studio looks: retry via legacy v2 when v3 engines fail.
    const shouldTryLegacyV2 =
      !useLegacyV2 &&
      (/avatar iv/i.test(msg) || /avatar v/i.test(msg)) &&
      !usesHeygenLegacyV2VideoApi(avatarId);

    if (shouldTryLegacyV2 && (!fallbackEngine || fallbackEngine === engine)) {
      try {
        const lookBody = await heygenV3Service.getAvatarLook(avatarId);
        if (usesHeygenLegacyV2VideoLook(lookBody) || isStudioOrDigitalTwinAvatarType(avatarType)) {
          const legacyHash = generateHeygenRequestHash({
            workspaceId,
            projectId,
            sceneId,
            avatarId,
            voiceId,
            script,
            avatarEngine: 'legacy_v2',
            outputFormat: normalizedOutputFormat,
          });
          const existingLegacy = await heygenDao.findHeygenResponseByRequestHash(legacyHash);
          if (existingLegacy) return existingLegacy;

          const createdLegacy = await createHeygenVideoJob(payloadBody, { useLegacyV2: true });
          return heygenDao.saveHeygenResponse({
            workspaceId,
            folderId: project.folderId,
            projectId,
            sceneId,
            videoId: createdLegacy.videoId,
            videoUrl: '',
            s3Key: null,
            requestHash: legacyHash,
            status: createdLegacy.status,
            rawResponse: createdLegacy.raw,
            triggeredByUserId: userId,
            billingContext: {
              avatarEngine: 'legacy_v2',
              heygenApiVersion: createdLegacy.apiVersion || 'v2',
              avatarType: avatarType || null,
              resolution: resolution || null,
              script,
              title: title || null,
              projectName: project.name,
              sceneName,
              estimatedCredits: estimate.athenaCredits,
              outputFormat: normalizedOutputFormat,
            },
          });
        }
      } catch {
        // fall through
      }
    }

    if (!fallbackEngine || fallbackEngine === engine) {
      throw err;
    }

    const fallbackRequestHash = generateHeygenRequestHash({
      workspaceId,
      projectId,
      sceneId,
      avatarId,
      voiceId,
      script,
      avatarEngine: fallbackEngine,
      outputFormat: normalizedOutputFormat,
    });

    const existingFallback = await heygenDao.findHeygenResponseByRequestHash(fallbackRequestHash);
    if (existingFallback) return existingFallback;

    const fallbackEstimate = calculateUsageCredits({
      feature: FEATURE.HEYGEN_VIDEO,
      durationSeconds: estimatedDuration,
      avatarEngine: fallbackEngine,
      avatarType,
      resolution,
    });

    const createdFallback = await createHeygenVideoJob(
      { ...payloadBody, avatarEngine: fallbackEngine },
      { useLegacyV2: false }
    );

    return heygenDao.saveHeygenResponse({
      workspaceId,
      folderId: project.folderId,
      projectId,
      sceneId,
      videoId: createdFallback.videoId,
      videoUrl: '',
      s3Key: null,
      requestHash: fallbackRequestHash,
      status: createdFallback.status,
      rawResponse: createdFallback.raw,
      triggeredByUserId: userId,
      billingContext: {
        avatarEngine: fallbackEngine,
        heygenApiVersion: createdFallback.apiVersion || 'v3',
        avatarType: avatarType || null,
        resolution: resolution || null,
        script,
        title: title || null,
        projectName: project.name,
        sceneName,
        estimatedCredits: fallbackEstimate.athenaCredits,
      },
    });
  }
};

async function pollLatestStatus(videoId) {
  let last = await heygenV3Service.getVideoStatus(videoId);
  for (let i = 0; i < MAX_POLL_ATTEMPTS - 1 && !isTerminalHeygenStatus(last.status); i += 1) {
    await sleep(POLL_INTERVAL_MS);
    last = await heygenV3Service.getVideoStatus(videoId);
  }
  return last;
}

async function downloadVideoBuffer(url) {
  const res = await fetch(url, { method: 'GET' });
  if (!res.ok) {
    throw new AppError(messages.HEYGEN_PROXY_FETCH_FAILED, 502);
  }
  return Buffer.from(await res.arrayBuffer());
}

function heygenPlaybackUrl(record, remote = null) {
  if (record?.s3Key) return null;
  const fromRemote = remote?.video_url;
  const fromRow = record?.videoUrl;
  const url = fromRemote || fromRow;
  return url && String(url).trim() !== '' ? String(url).trim() : null;
}

function isHeygenVideoPlayable(record) {
  return (
    record?.status === 'completed' &&
    Boolean(record.s3Key || heygenPlaybackUrl(record))
  );
}

function enrichHeygenVideoForClient(record) {
  const playbackUrl = heygenPlaybackUrl(record);
  return {
    ...record,
    fileSizeBytes: toJsonNumber(record.fileSizeBytes),
    playbackReady: isHeygenVideoPlayable(record),
    playbackUrl,
    s3Ready: Boolean(record.s3Key),
  };
}

function parseHeygenVideoSyncMode(sync) {
  if (sync === false || sync === 'false') return 'none';
  if (sync === 'full') return 'full';
  return 'status';
}

async function applyRemoteStatusToRecord(record, remote) {
  if (remote.status === 'failed') {
    return heygenDao.updateHeygenResponse(record.id, {
      status: 'failed',
      billingStatus: 'failed',
      rawResponse: remote.raw,
    });
  }

  if (remote.status !== 'completed') {
    return heygenDao.updateHeygenResponse(record.id, {
      status: remote.status,
      rawResponse: remote.raw,
    });
  }

  const playback = heygenPlaybackUrl(record, remote);
  return heygenDao.updateHeygenResponse(record.id, {
    status: 'completed',
    rawResponse: remote.raw,
    ...(playback ? { videoUrl: playback } : {}),
  });
}

async function copyHeygenVideoToS3(record, remote = null) {
  if (record.s3Key) return record;

  const sourceUrl = heygenPlaybackUrl(record, remote);
  if (!sourceUrl) return record;

  const buffer = await downloadVideoBuffer(sourceUrl);
  const owner = await storageAccounting.getWorkspaceOwnerOrThrow(record.workspaceId);
  await storageAccounting.recalculateUserStorageUsed(owner.id);
  await storageAccounting.assertOwnerCanFitAdditionalBytes(record.workspaceId, buffer.length);
  let folderId = record.folderId;
  if (!folderId) {
    const project = await getProjectInWorkspace(record.workspaceId, record.projectId);
    folderId = project.folderId;
  }

  const outputFormat = resolveHeygenOutputFormatFromRecord(record);
  const key = buildHeygenSceneVideoKey({
    workspaceId: record.workspaceId,
    folderId,
    projectId: record.projectId,
    sceneId: record.sceneId || 'scene',
    heygenVideoId: record.id,
    outputFormat,
  });
  const { url } = await uploadFileToKey(buffer, key, heygenOutputContentType(outputFormat));

  let updated = await heygenDao.updateHeygenResponse(record.id, {
    folderId,
    status: 'completed',
    s3Key: key,
    videoUrl: url,
    fileSizeBytes: buffer.length,
    rawResponse: remote?.raw ?? record.rawResponse,
  });
  updated = await chargeHeygenVideoIfNeeded(updated, remote);
  await projectStorageService.recalculateProjectStorage(record.projectId);
  await storageAccounting.recalculateUserStorageUsed(owner.id);
  return updated;
}

function queueHeygenVideoS3Upload(record, remote = null) {
  if (record.s3Key || s3UploadInflight.has(record.id)) return;
  const task = copyHeygenVideoToS3(record, remote)
    .catch(() => null)
    .finally(() => {
      s3UploadInflight.delete(record.id);
    });
  s3UploadInflight.set(record.id, task);
}

/**
 * Refresh HeyGen job status. When completed, stores HeyGen CDN URL for immediate canvas playback.
 */
async function refreshHeygenVideoStatus(record, { poll = true, queueS3 = true } = {}) {
  if (record.s3Key && record.status === 'completed') {
    return { record, remote: null };
  }

  const remote = poll
    ? await pollLatestStatus(record.videoId)
    : await heygenV3Service.getVideoStatus(record.videoId);
  const updated = await applyRemoteStatusToRecord(record, remote);

  if (updated.status === 'completed' && !updated.s3Key && queueS3) {
    queueHeygenVideoS3Upload(updated, remote);
  }

  return { record: updated, remote };
}

/**
 * Sync HeyGen job state and, when completed, copy MP4 to S3. Returns updated DB row.
 */
const syncHeygenVideoToS3AndDb = async (record, { poll = true } = {}) => {
  if (record.s3Key && record.status === 'completed') {
    return record;
  }

  const { record: refreshed, remote } = await refreshHeygenVideoStatus(record, {
    poll,
    queueS3: false,
  });

  if (refreshed.status !== 'completed' || refreshed.s3Key) {
    return refreshed;
  }

  const inflight = s3UploadInflight.get(refreshed.id);
  if (inflight) {
    const done = await inflight;
    return done || refreshed;
  }

  return copyHeygenVideoToS3(refreshed, remote);
};

const listProjectHeygenVideos = async (workspaceId, projectId) => {
  await getProjectInWorkspace(workspaceId, projectId);
  return heygenDao.listHeygenResponsesByProject(workspaceId, projectId);
};

const getProjectHeygenVideo = async (workspaceId, projectId, id, options = {}) => {
  await getProjectInWorkspace(workspaceId, projectId);
  const row = await heygenDao.findHeygenResponseByIdForProject(id, workspaceId, projectId);
  if (!row) {
    throw new AppError(messages.NOT_FOUND, 404);
  }

  const mode = parseHeygenVideoSyncMode(options.sync ?? 'status');
  if (mode === 'none') return row;
  if (mode === 'full') return syncHeygenVideoToS3AndDb(row);

  const { record } = await refreshHeygenVideoStatus(row);
  return record;
};

/**
 * Video is playable in the editor (HeyGen CDN or S3). Does not require S3.
 */
const assertHeygenVideoPlayable = async (workspaceId, projectId, id) => {
  let row = await getProjectHeygenVideo(workspaceId, projectId, id, { sync: 'status' });
  if (isHeygenVideoPlayable(row)) return row;

  if (row.status === 'completed') {
    row = await syncHeygenVideoToS3AndDb(row);
    if (isHeygenVideoPlayable(row)) return row;
  }

  throw new AppError(messages.HEYGEN_VIDEO_NOT_READY, 409);
};

/**
 * Sync HeyGen job and ensure MP4 exists in S3; throws 409 if not ready.
 */
const assertHeygenVideoReadyInS3 = async (workspaceId, projectId, id) => {
  const updated = await getProjectHeygenVideo(workspaceId, projectId, id, { sync: 'full' });
  if (updated.status !== 'completed' || !updated.s3Key) {
    throw new AppError(messages.HEYGEN_VIDEO_NOT_READY, 409);
  }
  return updated;
};

const getPresignedDownloadForVideo = async (
  workspaceId,
  projectId,
  id,
  expiresInSeconds = PRESIGN_DEFAULT_TTL
) => {
  const updated = await assertHeygenVideoPlayable(workspaceId, projectId, id);
  if (updated.s3Key) {
    const url = await getPresignedGetUrl(updated.s3Key, expiresInSeconds);
    return {
      presignedUrl: url,
      expiresInSeconds,
      playbackSource: 's3',
      heygenResponse: enrichHeygenVideoForClient(updated),
    };
  }

  const playbackUrl = heygenPlaybackUrl(updated);
  queueHeygenVideoS3Upload(updated);
  return {
    presignedUrl: playbackUrl,
    expiresInSeconds: null,
    playbackSource: 'heygen',
    heygenResponse: enrichHeygenVideoForClient(updated),
  };
};

/**
 * Bucket/key/region for render workers using IAM (GetObject), not presigned URLs.
 */

const getS3ObjectLocationForVideo = async (workspaceId, projectId, id) => {
  const updated = await assertHeygenVideoReadyInS3(workspaceId, projectId, id);
  const bucket = process.env.AWS_S3_BUCKET;
  const region = process.env.AWS_REGION;
  if (!bucket || !String(bucket).trim() || !region || !String(region).trim()) {
    throw new AppError(messages.INTERNAL_SERVER_ERROR, 500);
  }
  const key = updated.s3Key;
  const objectArn = `arn:aws:s3:::${bucket}/${key}`;
  return {
    bucket,
    key,
    region: String(region).trim(),
    objectArn,
    heygenVideo: enrichHeygenVideoForClient(updated),
  };
};

module.exports = {
  generateAvatarVideo,
  syncHeygenVideoToS3AndDb,
  listProjectHeygenVideos,
  getProjectHeygenVideo,
  assertHeygenVideoPlayable,
  assertHeygenVideoReadyInS3,
  getPresignedDownloadForVideo,
  getS3ObjectLocationForVideo,
  getProjectInWorkspace,
  enrichHeygenVideoForClient,
  heygenPlaybackUrl,
};
