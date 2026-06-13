const prisma = require('../../../shared/config/prismaClient');
const heygenDao = require('../heygen.dao');
const heygenV3Service = require('../../heygen/heygenV3.service');
const { generateHeygenRequestHash } = require('../../../shared/utils/requestHash');
const { uploadFileToKey, getPresignedGetUrl } = require('../../s3/s3.service');
const AppError = require('../../../shared/utils/AppError');
const messages = require('../../../shared/utils/messages');
const { buildHeygenSceneVideoKey } = require('../../../shared/utils/videoStorageKeys');
const projectStorageService = require('../../project/projectStorage.service');
const {
  HEYGEN_AVATAR_ENGINES,
  normalizeHeygenAvatarEngine,
  buildHeygenVideoEnginePayload,
} = require('../../../shared/constants/heygen');
const creditLedger = require('../../credit/creditLedger.service');
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

  const payload = {
    type: 'avatar',
    avatar_id: avatarId,
    engine: buildHeygenVideoEnginePayload(engine),
    title,
    resolution,
    aspect_ratio: aspectRatio,
    background: {
      type: 'color',
      value: backgroundColor,
    },
    remove_background: removeBackground ?? false,
    output_format: outputFormat || 'mp4',
    script,
    voice_id: voiceId,
    voice_settings,
  };

  if (shouldIncludeExpressiveness(engine, avatarType, expressiveness)) {
    payload.expressiveness = expressiveness;
  }

  return payload;
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
  const engine = normalizeHeygenAvatarEngine(avatarEngine);

  const requestHash = generateHeygenRequestHash({
    workspaceId,
    projectId,
    sceneId,
    avatarId,
    voiceId,
    script,
    avatarEngine: engine,
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

  const jsonBody = buildHeyGenVideoPayload({
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
    outputFormat,
  });

  try {
    const created = await heygenV3Service.createVideo(jsonBody);
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
      avatarEngine: engine,
      avatarType: avatarType || null,
      resolution: resolution || null,
      script,
      title: title || null,
      projectName: project.name,
      sceneName,
      estimatedCredits: estimate.athenaCredits,
    },
    });
  } catch (err) {
    // Defensive retry: if the look lied about Avatar IV support (or we couldn't
    // extract supported engines correctly), retry with Avatar V.
    const msg = String(err?.message || '');
    if (
      engine === HEYGEN_AVATAR_ENGINES.IV &&
      err instanceof AppError &&
      err.statusCode === 400 &&
      /avatar iv/i.test(msg)
    ) {
      const fallbackEngine = HEYGEN_AVATAR_ENGINES.V;
      const fallbackRequestHash = generateHeygenRequestHash({
        workspaceId,
        projectId,
        sceneId,
        avatarId,
        voiceId,
        script,
        avatarEngine: fallbackEngine,
      });

      const existingFallback = await heygenDao.findHeygenResponseByRequestHash(fallbackRequestHash);
      if (existingFallback) return existingFallback;

      const fallbackJsonBody = buildHeyGenVideoPayload({
        avatarId,
        avatarEngine: fallbackEngine,
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
      });

      const fallbackEstimate = calculateUsageCredits({
        feature: FEATURE.HEYGEN_VIDEO,
        durationSeconds: estimatedDuration,
        avatarEngine: fallbackEngine,
        avatarType,
        resolution,
      });

      const createdFallback = await heygenV3Service.createVideo(fallbackJsonBody);
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

    throw err;
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
  let folderId = record.folderId;
  if (!folderId) {
    const project = await getProjectInWorkspace(record.workspaceId, record.projectId);
    folderId = project.folderId;
  }

  const key = buildHeygenSceneVideoKey({
    workspaceId: record.workspaceId,
    folderId,
    projectId: record.projectId,
    sceneId: record.sceneId || 'scene',
    heygenVideoId: record.id,
  });
  const { url } = await uploadFileToKey(buffer, key, 'video/mp4');

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
    heygenVideo: updated,
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
