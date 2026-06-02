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
  extractSupportedApiEnginesFromLook,
} = require('../../../shared/constants/heygen');

const POLL_INTERVAL_MS = 2500;
const MAX_POLL_ATTEMPTS = 20;
const PRESIGN_DEFAULT_TTL = 300;

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

async function assertLookSupportsAvatarEngine(avatarId, avatarEngine) {
  let raw;
  try {
    raw = await heygenV3Service.getAvatarLook(avatarId);
  } catch (err) {
    if (err instanceof AppError && err.statusCode === 404) {
      return;
    }
    throw err;
  }
  const supported = extractSupportedApiEnginesFromLook(raw);
  if (!supported || supported.length === 0) {
    return;
  }
  if (!supported.includes(avatarEngine)) {
    throw new AppError(
      `${messages.HEYGEN_AVATAR_ENGINE_UNSUPPORTED} (${avatarEngine}). Supported: ${supported.join(', ')}`,
      400
    );
  }
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
const generateAvatarVideo = async (input) => {
  const {
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

  await assertLookSupportsAvatarEngine(avatarId, engine);

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
  });
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

/**
 * Sync HeyGen job state and, when completed, copy MP4 to S3. Returns updated DB row.
 */
const syncHeygenVideoToS3AndDb = async (record) => {
  if (record.s3Key && record.status === 'completed') {
    return record;
  }

  const remote = await pollLatestStatus(record.videoId);

  if (remote.status === 'failed') {
    return heygenDao.updateHeygenResponse(record.id, {
      status: 'failed',
      rawResponse: remote.raw,
    });
  }

  if (remote.status !== 'completed') {
    return heygenDao.updateHeygenResponse(record.id, {
      status: remote.status,
      rawResponse: remote.raw,
    });
  }

  if (!remote.video_url) {
    return heygenDao.updateHeygenResponse(record.id, {
      status: remote.status,
      rawResponse: remote.raw,
    });
  }

  if (record.s3Key) {
    return heygenDao.updateHeygenResponse(record.id, {
      status: 'completed',
      rawResponse: remote.raw,
    });
  }

  const buffer = await downloadVideoBuffer(remote.video_url);
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

  const updated = await heygenDao.updateHeygenResponse(record.id, {
    folderId,
    status: 'completed',
    s3Key: key,
    videoUrl: url,
    fileSizeBytes: buffer.length,
    rawResponse: remote.raw,
  });
  await projectStorageService.recalculateProjectStorage(record.projectId);
  return updated;
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
  if (options.sync !== false) {
    return syncHeygenVideoToS3AndDb(row);
  }
  return row;
};

/**
 * Sync HeyGen job and ensure MP4 exists in S3; throws 409 if not ready.
 */
const assertHeygenVideoReadyInS3 = async (workspaceId, projectId, id) => {
  const updated = await getProjectHeygenVideo(workspaceId, projectId, id, { sync: true });
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
  const updated = await assertHeygenVideoReadyInS3(workspaceId, projectId, id);
  const url = await getPresignedGetUrl(updated.s3Key, expiresInSeconds);
  return { presignedUrl: url, expiresInSeconds, heygenResponse: updated };
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
  assertHeygenVideoReadyInS3,
  getPresignedDownloadForVideo,
  getS3ObjectLocationForVideo,
  getProjectInWorkspace,
};
