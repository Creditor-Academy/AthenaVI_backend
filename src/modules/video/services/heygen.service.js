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
  isAvatar6Engine,
  normalizeHeygenAvatarEngine,
  usesHeygenLegacyV2VideoApi,
  isAvatarIiiOnlyLegacyLook,
  usesHeygenLegacyV2VideoLook,
  buildHeygenVideoEnginePayload,
  resolveVideoPlanForLook,
  isStudioOrDigitalTwinAvatarType,
} = require('../../../shared/constants/heygen');
const { isHeygenPreferV3VideoEnabled } = require('../../../shared/config/heygenVideoMigration');
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
const logger = require('../../../shared/utils/logger');
const { validateVideoVoiceSettings } = require('../../../shared/utils/heygenVoiceCapabilities');
const {
  withHeygenVideoCreateLock,
  runHeygenCreateAttempt,
} = require('./heygenCreateCoordinator');

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

/** HeyGen /v3/videos voice_settings bounds; speech narration allows up to 2x, so clamp here. */
const HEYGEN_VOICE_SPEED_MIN = 0.5;
const HEYGEN_VOICE_SPEED_MAX = 1.5;
const HEYGEN_VOICE_VOLUME_MAX = 1;

function clampNumber(value, min, max) {
  const n = Number(value);
  if (!Number.isFinite(n)) return min;
  return Math.min(max, Math.max(min, n));
}

/** Avatar 6 renders at 1080p minimum on HeyGen. */
function resolutionForEngine(engine, resolution) {
  if (isAvatar6Engine(engine) && resolution === '720p') return '1080p';
  return resolution;
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
    motionExpressiveness,
  } = body;

  // Engine is always named (HeyGen fails late if it is missing). The model is left out:
  // HeyGen Voice defaults to heygen-voice-1, and a professional voice clone rejects any model.
  const engine_settings =
    voiceSettings?.engine_settings && typeof voiceSettings.engine_settings === 'object'
      ? voiceSettings.engine_settings
      : { engine_type: 'heygen_voice' };

  const voice_settings = {
    speed: clampNumber(voiceSettings?.speed ?? 1, HEYGEN_VOICE_SPEED_MIN, HEYGEN_VOICE_SPEED_MAX),
    pitch: voiceSettings?.pitch ?? 0,
    ...(voiceSettings?.volume != null && {
      volume: clampNumber(voiceSettings.volume, 0, HEYGEN_VOICE_VOLUME_MAX),
    }),
    ...(voiceSettings?.locale && { locale: voiceSettings.locale }),
    engine_settings,
  };

  const engine = normalizeHeygenAvatarEngine(avatarEngine);
  const format = normalizeHeygenOutputFormat(outputFormat);

  const payload = {
    type: 'avatar',
    avatar_id: avatarId,
    engine: buildHeygenVideoEnginePayload(engine, { motionExpressiveness }),
    title,
    resolution: resolutionForEngine(engine, resolution),
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

function buildHeygenVideoBillingContext({
  engine,
  created,
  avatarType,
  resolution,
  script,
  title,
  projectName,
  sceneName,
  estimatedCredits,
  outputFormat,
}) {
  return {
    avatarEngine: engine,
    heygenApiVersion: created.apiVersion || 'v3',
    avatarType: avatarType || null,
    resolution: resolutionForEngine(engine, resolution) || null,
    script,
    title: title || null,
    projectName,
    sceneName,
    estimatedCredits,
    outputFormat,
    preferV3Video: isHeygenPreferV3VideoEnabled(),
  };
}

async function resolveVideoEngineForAvatar(avatarId, avatarEngine, avatarType) {
  try {
    const lookBody = await heygenV3Service.getAvatarLook(avatarId);
    const plan = resolveVideoPlanForLook(lookBody, avatarEngine, avatarType);
    if (plan.engine == null) {
      throw new AppError(messages.HEYGEN_AVATAR_ENGINE_UNSUPPORTED, 400);
    }
    return { engine: plan.engine, plan };
  } catch (err) {
    if (err instanceof AppError) throw err;
    const requested = normalizeHeygenAvatarEngine(avatarEngine);
    let engine = requested;
    if (usesHeygenLegacyV2VideoApi(avatarId)) {
      engine = isStudioOrDigitalTwinAvatarType(avatarType)
        ? HEYGEN_AVATAR_ENGINES.III
        : HEYGEN_AVATAR_ENGINES.IV;
    } else if (isStudioOrDigitalTwinAvatarType(avatarType)) {
      engine = HEYGEN_AVATAR_ENGINES.V;
    }
    return { engine, plan: null };
  }
}

async function submitHeygenVideoAttempt({ payloadBody, attemptHash, retryRow }) {
  const jsonBody = buildHeyGenVideoPayload(payloadBody);
  return runHeygenCreateAttempt({
    attemptHash,
    retryRow,
    jsonBody,
    execute: (idempotencyKey) => heygenV3Service.createVideo(jsonBody, { idempotencyKey }),
    findExisting: async () => (await findReusableOrRetryableResponse(attemptHash)).existing,
  });
}

/**
 * Start HeyGen avatar video generation; idempotent per request hash (includes sceneId).
 */
/**
 * Billed length: HeyGen's reported duration. `remote` is not always available (the download endpoint
 * queues the copy without it), so fall back to the duration kept in the stored status response, and
 * only then to the script estimate.
 */
function resolveHeygenVideoDurationSeconds(record, remote) {
  const fromRemote = Number(remote?.duration);
  if (fromRemote > 0) return fromRemote;

  const raw = record.rawResponse && typeof record.rawResponse === 'object' ? record.rawResponse : null;
  const fromRaw = Number(raw?.data?.duration ?? raw?.duration);
  if (fromRaw > 0) return fromRaw;

  return estimateDurationFromScript(record.billingContext?.script || record.billingContext?.scriptText);
}

function priceHeygenVideoRecord(record, remote, avatarEngine) {
  const durationSeconds = resolveHeygenVideoDurationSeconds(record, remote);
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
  return { durationSeconds, billingContext, pricing };
}

function isHeygenVideoBillingSettled(record) {
  return record.billingStatus === 'charged' || record.billingStatus === 'skipped';
}

/**
 * Refuse early, before downloading the video, when the workspace cannot cover the charge. Without
 * this a low balance would re-download the whole MP4 on every status check just to be refused.
 */
async function assertHeygenVideoAffordable(record, remote) {
  if (isHeygenVideoBillingSettled(record) || !record.triggeredByUserId) return;
  const { pricing } = priceHeygenVideoRecord(record, remote);
  await creditLedger.assertCanAfford({
    scope: SCOPE.WORKSPACE,
    workspaceId: record.workspaceId,
    userId: record.triggeredByUserId,
    estimatedAc: pricing.athenaCredits,
  });
}

async function chargeHeygenVideoIfNeeded(record, remote, avatarEngine) {
  if (isHeygenVideoBillingSettled(record)) {
    return record;
  }
  if (!record.triggeredByUserId) {
    return heygenDao.updateHeygenResponse(record.id, { billingStatus: 'skipped' });
  }

  const { durationSeconds, billingContext, pricing } = priceHeygenVideoRecord(
    record,
    remote,
    avatarEngine
  );
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

/**
 * Reject a locale / engine / model combination HeyGen does not offer, before anything is created or
 * charged. If the capabilities list cannot be read, skip the check and let HeyGen decide.
 */
async function assertVideoVoiceSettingsSupported(voiceSettings) {
  if (!voiceSettings?.locale && !voiceSettings?.engine_settings) return;
  let capabilities;
  try {
    capabilities = await heygenV3Service.getVideoVoiceCapabilities();
  } catch (err) {
    logger.warn('heygen_voice_capabilities_unavailable', {
      error: String(err?.message || err).slice(0, 300),
    });
    return;
  }
  const result = validateVideoVoiceSettings(capabilities, voiceSettings);
  if (!result.ok) {
    throw new AppError(result.message, 400);
  }
}

/**
 * A failed job that was never billed and left no stored file can be generated again. Without this the
 * request hash (which ignores everything but avatar, voice, script, engine, format) keeps returning
 * the same failed row, so a scene could never be retried after a transient or plan-gate failure.
 */
function isRetryableFailedHeygenRow(row) {
  return Boolean(
    row &&
      row.status === 'failed' &&
      !row.s3Key &&
      row.billingStatus !== 'charged' &&
      !(Number(row.creditsCharged) > 0)
  );
}

/** Existing row for this hash: returned as-is unless it is a retryable failure. */
async function findReusableOrRetryableResponse(requestHash) {
  const existing = await heygenDao.findHeygenResponseByRequestHash(requestHash);
  if (!existing) return { existing: null, retryRow: null };
  if (isRetryableFailedHeygenRow(existing)) return { existing: null, retryRow: existing };
  return { existing, retryRow: null };
}

function logDiscardedDuplicateHeygenJob(rowId, keptVideoId, discardedVideoId) {
  if (keptVideoId && discardedVideoId && keptVideoId !== discardedVideoId) {
    logger.warn('heygen_video_duplicate_job_discarded', {
      rowId,
      keptVideoId,
      discardedVideoId,
    });
  }
}

/**
 * Save a newly created HeyGen job. For a retry the failed row is reused in place (the hash is unique,
 * and the row id keeps scene references, storage key and billing idempotency key stable).
 * Also recovers cleanly if a concurrent first-create wins the unique `requestHash` constraint (`P2002`).
 */
async function persistHeygenResponse(data, retryRow) {
  if (!retryRow) {
    try {
      return await heygenDao.saveHeygenResponse(data);
    } catch (err) {
      if (err?.code === 'P2002' && data?.requestHash) {
        const raced = await heygenDao.findHeygenResponseByRequestHash(data.requestHash);
        if (raced && !isRetryableFailedHeygenRow(raced)) {
          logDiscardedDuplicateHeygenJob(raced.id, raced.videoId, data.videoId);
          return raced;
        }
        if (raced && isRetryableFailedHeygenRow(raced)) {
          const { count, row } = await heygenDao.reuseFailedHeygenResponse(raced.id, data);
          if (count === 0 && row) {
            logDiscardedDuplicateHeygenJob(row.id, row.videoId, data.videoId);
          }
          if (row) return row;
        }
      }
      throw err;
    }
  }
  const { count, row } = await heygenDao.reuseFailedHeygenResponse(retryRow.id, data);
  if (count === 0 && row) {
    logDiscardedDuplicateHeygenJob(row.id, row.videoId, data.videoId);
  }
  return row;
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
    motionExpressiveness,
  } = input;

  const project = await getProjectInWorkspace(workspaceId, projectId);
  const sceneName = resolveSceneNameFromProjectData(project.data, sceneId);
  const normalizedOutputFormat = normalizeHeygenOutputFormat(outputFormat);
  const { engine, plan } = await resolveVideoEngineForAvatar(avatarId, avatarEngine, avatarType);

  const requestHash = generateHeygenRequestHash({
    workspaceId,
    projectId,
    sceneId,
    avatarId,
    voiceId,
    script,
    avatarEngine: engine,
    outputFormat: normalizedOutputFormat,
    motionExpressiveness,
  });

  const { existing: existingResponse } = await findReusableOrRetryableResponse(requestHash);
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
  await assertVideoVoiceSettingsSupported(voiceSettings);

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
    motionExpressiveness,
    voiceSettings,
    removeBackground,
    outputFormat: normalizedOutputFormat,
  };

  return withHeygenVideoCreateLock(
    {
      requestHash,
      loadRowById: async (id) => {
        const row = await heygenDao.findHeygenResponseByIdForProject(id, workspaceId, projectId);
        return row && !isRetryableFailedHeygenRow(row) ? row : null;
      },
      loadReusableByHash: async () => (await findReusableOrRetryableResponse(requestHash)).existing,
    },
    async () => {
      const { existing: latestExisting, retryRow } =
        await findReusableOrRetryableResponse(requestHash);
      if (latestExisting) {
        return latestExisting;
      }

      let primaryAttempt;
      try {
        primaryAttempt = await submitHeygenVideoAttempt({
          payloadBody,
          attemptHash: requestHash,
          retryRow,
        });
      } catch (err) {
        const msg = String(err?.message || '');
        // Plan gating may come back as 402/403 (`plan_upgrade_required`) rather than 400.
        const isAvatar6Gate =
          err instanceof AppError &&
          [400, 402, 403].includes(err.statusCode) &&
          /avatar 6/i.test(msg);
        if (!(err instanceof AppError) || (err.statusCode !== 400 && !isAvatar6Gate)) {
          throw err;
        }

        const supported = plan?.supportedApiEngines || [];
        const supportsIv = supported.includes(HEYGEN_AVATAR_ENGINES.IV);
        const supportsV = supported.includes(HEYGEN_AVATAR_ENGINES.V);
        let fallbackEngine = null;

        // Look metadata can lag HeyGen's plan gating ("available only with Avatar 6 Pro or Turbo").
        if (isAvatar6Gate && !isAvatar6Engine(engine)) {
          fallbackEngine =
            [HEYGEN_AVATAR_ENGINES.AVATAR_6_TURBO, HEYGEN_AVATAR_ENGINES.AVATAR_6].find((e) =>
              supported.includes(e)
            ) || HEYGEN_AVATAR_ENGINES.AVATAR_6_TURBO;
        } else if (
          // Only retry V→IV for non-studio looks: studio/digital-twin looks should not get IV
          // unless their supported_api_engines list it (checked via supportsIv).
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

        const shouldTryAvatarIii =
          (/avatar iv/i.test(msg) || /avatar v/i.test(msg)) &&
          (!fallbackEngine || fallbackEngine === engine);

        if (shouldTryAvatarIii && engine !== HEYGEN_AVATAR_ENGINES.III) {
          try {
            const lookBody = await heygenV3Service.getAvatarLook(avatarId);
            const canTryIii =
              isAvatarIiiOnlyLegacyLook(lookBody) ||
              usesHeygenLegacyV2VideoLook(lookBody) ||
              usesHeygenLegacyV2VideoApi(avatarId) ||
              plan?.supportedApiEngines?.includes(HEYGEN_AVATAR_ENGINES.III);

            if (canTryIii) {
              const iiiHash = generateHeygenRequestHash({
                workspaceId,
                projectId,
                sceneId,
                avatarId,
                voiceId,
                script,
                avatarEngine: HEYGEN_AVATAR_ENGINES.III,
                outputFormat: normalizedOutputFormat,
              });
              const { existing: existingIii, retryRow: retryIii } =
                await findReusableOrRetryableResponse(iiiHash);
              if (existingIii) return existingIii;

              const iiiEstimate = calculateUsageCredits({
                feature: FEATURE.HEYGEN_VIDEO,
                durationSeconds: estimatedDuration,
                avatarEngine: HEYGEN_AVATAR_ENGINES.III,
                avatarType,
                resolution,
              });

              const iiiAttempt = await submitHeygenVideoAttempt({
                payloadBody: {
                  ...payloadBody,
                  avatarEngine: HEYGEN_AVATAR_ENGINES.III,
                },
                attemptHash: iiiHash,
                retryRow: retryIii,
              });
              if (iiiAttempt.replayedExisting) {
                return iiiAttempt.replayedExisting;
              }
              const { created: createdIii } = iiiAttempt;
              return persistHeygenResponse(
                {
                  workspaceId,
                  folderId: project.folderId,
                  projectId,
                  sceneId,
                  videoId: createdIii.videoId,
                  videoUrl: '',
                  s3Key: null,
                  requestHash: iiiHash,
                  status: createdIii.status,
                  rawResponse: createdIii.raw,
                  triggeredByUserId: userId,
                  billingContext: buildHeygenVideoBillingContext({
                    engine: HEYGEN_AVATAR_ENGINES.III,
                    created: createdIii,
                    avatarType,
                    resolution,
                    script,
                    title,
                    projectName: project.name,
                    sceneName,
                    estimatedCredits: iiiEstimate.athenaCredits,
                    outputFormat: normalizedOutputFormat,
                  }),
                },
                retryIii
              );
            }
          } catch (iiiErr) {
            if (iiiErr instanceof AppError && iiiErr.statusCode === 409) {
              throw iiiErr;
            }
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
          motionExpressiveness,
        });

        const { existing: existingFallback, retryRow: retryFallback } =
          await findReusableOrRetryableResponse(fallbackRequestHash);
        if (existingFallback) return existingFallback;

        const fallbackEstimate = calculateUsageCredits({
          feature: FEATURE.HEYGEN_VIDEO,
          durationSeconds: estimatedDuration,
          avatarEngine: fallbackEngine,
          avatarType,
          resolution,
        });
        if (fallbackEstimate.athenaCredits > estimate.athenaCredits) {
          await creditLedger.assertCanAfford({
            scope: SCOPE.WORKSPACE,
            workspaceId,
            userId,
            estimatedAc: fallbackEstimate.athenaCredits,
          });
        }

        const fallbackAttempt = await submitHeygenVideoAttempt({
          payloadBody: {
            ...payloadBody,
            avatarEngine: fallbackEngine,
          },
          attemptHash: fallbackRequestHash,
          retryRow: retryFallback,
        });
        if (fallbackAttempt.replayedExisting) {
          return fallbackAttempt.replayedExisting;
        }
        const { created: createdFallback } = fallbackAttempt;

        return persistHeygenResponse(
          {
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
            billingContext: buildHeygenVideoBillingContext({
              engine: fallbackEngine,
              created: createdFallback,
              avatarType,
              resolution,
              script,
              title,
              projectName: project.name,
              sceneName,
              estimatedCredits: fallbackEstimate.athenaCredits,
              outputFormat: normalizedOutputFormat,
            }),
          },
          retryFallback
        );
      }

      if (primaryAttempt.replayedExisting) {
        return primaryAttempt.replayedExisting;
      }
      const { created } = primaryAttempt;
      return persistHeygenResponse(
        {
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
          billingContext: buildHeygenVideoBillingContext({
            engine,
            created,
            avatarType,
            resolution,
            script,
            title,
            projectName: project.name,
            sceneName,
            estimatedCredits: estimate.athenaCredits,
            outputFormat: normalizedOutputFormat,
          }),
        },
        retryRow
      );
    }
  );
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

  // Billing gates the stored copy. HeyGen has already produced (and billed us for) this video, so a
  // stored, unbilled file would be free for good: once `s3Key` is set, status checks return early
  // and never charge again. Until the charge succeeds the row stays `completed` without `s3Key`,
  // still plays from the HeyGen URL, and every later status check retries this whole step.
  await assertHeygenVideoAffordable(record, remote);

  const buffer = await downloadVideoBuffer(sourceUrl);
  const owner = await storageAccounting.getWorkspaceOwnerOrThrow(record.workspaceId);
  await storageAccounting.recalculateUserStorageUsed(owner.id);
  await storageAccounting.assertOwnerCanFitAdditionalBytes(record.workspaceId, buffer.length);
  let folderId = record.folderId;
  if (!folderId) {
    const project = await getProjectInWorkspace(record.workspaceId, record.projectId);
    folderId = project.folderId;
  }

  // Charge after the quota check (which can refuse without billing) and before the upload. If the
  // upload then fails the video stays billed once (the charge is idempotent) and is stored on retry.
  await chargeHeygenVideoIfNeeded(record, remote);

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

  const updated = await heygenDao.updateHeygenResponse(record.id, {
    folderId,
    status: 'completed',
    s3Key: key,
    videoUrl: url,
    fileSizeBytes: buffer.length,
    rawResponse: remote?.raw ?? record.rawResponse,
  });
  try {
    await projectStorageService.recalculateProjectStorage(record.projectId);
    await storageAccounting.recalculateUserStorageUsed(owner.id);
  } catch (err) {
    logger.warn('heygen_video_storage_recalc_failed', {
      heygenVideoId: record.id,
      error: String(err?.message || err).slice(0, 300),
    });
  }
  return updated;
}

function queueHeygenVideoS3Upload(record, remote = null) {
  if (record.s3Key || s3UploadInflight.has(record.id)) return;
  const task = copyHeygenVideoToS3(record, remote)
    .catch((err) => {
      // Background copy: the next status check retries it. Log so a refused charge is not invisible.
      logger.warn('heygen_video_copy_failed', {
        heygenVideoId: record.id,
        statusCode: err?.statusCode ?? null,
        error: String(err?.message || err).slice(0, 300),
      });
      return null;
    })
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
  buildHeyGenVideoPayload,
  isRetryableFailedHeygenRow,
  findReusableOrRetryableResponse,
  persistHeygenResponse,
  copyHeygenVideoToS3,
  resolveHeygenVideoDurationSeconds,
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
