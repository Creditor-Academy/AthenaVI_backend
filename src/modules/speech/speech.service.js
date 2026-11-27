const prisma = require('../../shared/config/prismaClient');
const speechDao = require('./speech.dao');
const heygenV3Service = require('../heygen/heygenV3.service');
const { generateSpeechRequestHash } = require('../../shared/utils/requestHash');
const { uploadFileToKey, getPresignedGetUrl, deleteFile } = require('../s3/s3.service');
const { downloadRemote } = require('../../shared/utils/downloadRemote');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const { toJsonNumber } = require('../../shared/utils/byteSize');
const { buildSpeechSceneAudioKey } = require('../../shared/utils/videoStorageKeys');
const projectStorageService = require('../project/projectStorage.service');
const creditLedger = require('../credit/creditLedger.service');
const logger = require('../../shared/utils/logger');
const {
  truncateText,
  resolveSceneNameFromProjectData,
} = require('../credit/creditHistory.enrich');
const {
  FEATURE,
  SCOPE,
  calculateUsageCredits,
  estimateDurationFromScript,
} = require('../../shared/config/creditPricing');

const PRESIGN_DEFAULT_TTL = 300;
const MAX_AUDIO_BYTES = 50 * 1024 * 1024;

async function getProjectInWorkspace(workspaceId, projectId) {
  const project = await prisma.project.findFirst({
    where: { id: projectId, workspaceId },
    select: { id: true, folderId: true, name: true, data: true },
  });
  if (!project) {
    throw new AppError(messages.NOT_FOUND, 404);
  }
  return project;
}

function normalizeHeygenSpeechResponse(body) {
  const data = body && typeof body === 'object' && 'data' in body ? body.data : body;
  if (!data || typeof data !== 'object') {
    throw new AppError(messages.HEYGEN_REQUEST_FAILED, 502);
  }
  const audioUrl = data.audio_url && String(data.audio_url).trim();
  if (!audioUrl) {
    throw new AppError(messages.HEYGEN_REQUEST_FAILED, 502);
  }
  return {
    audioUrl,
    durationSec: Number(data.duration) > 0 ? Number(data.duration) : null,
    wordTimestamps: data.word_timestamps ?? null,
    raw: body,
  };
}

function isSpeechPlayable(record) {
  return record?.status === 'completed' && Boolean(record.s3Key);
}

/**
 * A failed narration that was never billed can be generated again. Without this the request hash
 * keeps returning the same failed row, so a scene could not be retried after e.g. topping up credits.
 */
function isRetryableFailedSpeech(row) {
  return Boolean(row && row.status === 'failed' && row.billingStatus !== 'charged');
}

function enrichSpeechGenerationForClient(record) {
  return {
    ...record,
    fileSizeBytes: toJsonNumber(record.fileSizeBytes),
    playbackReady: isSpeechPlayable(record),
    playbackUrl: null,
    s3Ready: Boolean(record.s3Key),
  };
}

async function chargeSpeechIfNeeded(record) {
  if (record.billingStatus === 'charged' || record.billingStatus === 'skipped') {
    return record;
  }
  if (!record.triggeredByUserId) {
    return speechDao.updateSpeechGeneration(record.id, { billingStatus: 'skipped' });
  }

  const billingContext =
    record.billingContext && typeof record.billingContext === 'object'
      ? record.billingContext
      : {};

  const durationSeconds =
    record.durationSec != null && Number(record.durationSec) > 0
      ? Number(record.durationSec)
      : estimateDurationFromScript(record.script || billingContext.script);

  const pricing = calculateUsageCredits({
    feature: FEATURE.SPEECH_GENERATION,
    durationSeconds,
    characters: String(record.script || billingContext.script || '').length,
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
    idempotencyKey: `speech-generation:${record.id}`,
    metadata: {
      feature: FEATURE.SPEECH_GENERATION,
      speechGenerationId: record.id,
      projectId: record.projectId,
      projectName,
      sceneId: record.sceneId || null,
      sceneName,
      voiceId: record.voiceId,
      scriptPreview: truncateText(record.script || billingContext.script),
      durationSeconds,
      heygenUsdCost: pricing.heygenUsdCost,
      scope: SCOPE.WORKSPACE,
    },
    reference: record.id,
  });

  return speechDao.updateSpeechGeneration(record.id, {
    billingStatus: 'charged',
    creditsCharged: pricing.athenaCredits,
    billedDurationSec: durationSeconds,
  });
}

async function generateProjectSpeech(input) {
  const {
    userId,
    workspaceId,
    projectId,
    sceneId,
    voiceId,
    script,
    inputType,
    speed,
    language,
    locale,
  } = input;

  const project = await getProjectInWorkspace(workspaceId, projectId);
  const normalizedSpeed = speed != null ? Number(speed) : 1;
  const normalizedInputType = inputType || 'text';
  const normalizedLocale =
    locale != null && String(locale).trim() !== '' ? String(locale).trim() : null;
  const normalizedLanguage =
    language != null && String(language).trim() !== '' ? String(language).trim() : null;

  const requestHash = generateSpeechRequestHash({
    workspaceId,
    projectId,
    sceneId,
    voiceId,
    script,
    speed: normalizedSpeed,
    inputType: normalizedInputType,
    locale: normalizedLocale,
  });

  const existing = await speechDao.findSpeechGenerationByRequestHash(requestHash);
  if (existing && !isRetryableFailedSpeech(existing)) {
    return existing;
  }

  const estimatedDuration = estimateDurationFromScript(script);
  const estimate = calculateUsageCredits({
    feature: FEATURE.SPEECH_GENERATION,
    durationSeconds: estimatedDuration,
    characters: String(script || '').length,
  });
  await creditLedger.assertCanAfford({
    scope: SCOPE.WORKSPACE,
    workspaceId,
    userId,
    estimatedAc: estimate.athenaCredits,
  });

  await heygenV3Service.assertVoiceSupportsStarfishSpeech(voiceId);

  const sceneName = resolveSceneNameFromProjectData(project.data, sceneId);
  const billingContext = {
    script,
    voiceId,
    sceneId,
    inputType: normalizedInputType,
    speed: normalizedSpeed,
    locale: normalizedLocale,
    projectName: project.name || null,
    sceneName,
    estimatedCredits: estimate.athenaCredits,
  };

  let pending;
  if (existing) {
    // Retry of a failed, unbilled narration: re-arm the same row (the S3 key is built from its id).
    pending = await speechDao.claimFailedSpeechGeneration(existing.id, {
      folderId: project.folderId,
      voiceId,
      script,
      inputType: normalizedInputType,
      speed: normalizedSpeed,
      locale: normalizedLocale,
      language: normalizedLanguage,
      triggeredByUserId: userId,
      billingContext,
    });
    if (!pending) {
      // Another request claimed it first; hand back whatever the row is now.
      return speechDao.findSpeechGenerationByRequestHash(requestHash);
    }
  } else {
    pending = await speechDao.saveSpeechGeneration({
      workspaceId,
      folderId: project.folderId,
      projectId,
      sceneId,
      voiceId,
      script,
      inputType: normalizedInputType,
      speed: normalizedSpeed,
      locale: normalizedLocale,
      language: normalizedLanguage,
      requestHash,
      status: 'processing',
      triggeredByUserId: userId,
      billingContext,
    });
  }

  let updated;
  let uploadedKey = null;
  try {
    const heygenPayload = {
      text: script,
      voice_id: voiceId,
      input_type: normalizedInputType,
      speed: normalizedSpeed,
    };
    if (normalizedLanguage) heygenPayload.language = normalizedLanguage;
    if (normalizedLocale) heygenPayload.locale = normalizedLocale;

    const rawBody = await heygenV3Service.generateSpeechPreview(heygenPayload);
    const speech = normalizeHeygenSpeechResponse(rawBody);
    const buffer = await downloadRemote(speech.audioUrl, { maxBytes: MAX_AUDIO_BYTES });

    const s3Key = buildSpeechSceneAudioKey({
      workspaceId,
      folderId: project.folderId,
      projectId,
      sceneId,
      speechId: pending.id,
    });
    const { url } = await uploadFileToKey(buffer, s3Key, 'audio/mpeg');
    uploadedKey = s3Key;
    const durationSec = speech.durationSec ?? estimatedDuration;

    updated = await speechDao.updateSpeechGeneration(pending.id, {
      heygenAudioUrl: speech.audioUrl,
      audioUrl: url,
      s3Key,
      fileSizeBytes: buffer.length,
      durationSec,
      wordTimestamps: speech.wordTimestamps,
      status: 'completed',
      rawResponse: speech.raw,
    });

    // Charge last: nothing after this may flip a billed row to failed.
    updated = await chargeSpeechIfNeeded(updated);
  } catch (err) {
    // If the audio was uploaded but the row was never billed (e.g. the charge was refused), do not
    // leave an unreachable object behind or a failed row pointing at it.
    let clearedStorage = {};
    if (uploadedKey) {
      try {
        const current = await speechDao.findSpeechGenerationByIdForProject(
          pending.id,
          workspaceId,
          projectId
        );
        if (current?.billingStatus !== 'charged') {
          await deleteFile(uploadedKey);
          clearedStorage = { audioUrl: '', s3Key: null, fileSizeBytes: null };
        }
      } catch (cleanupError) {
        logger.warn('speech_failed_upload_cleanup_failed', {
          speechGenerationId: pending.id,
          error: String(cleanupError?.message || cleanupError).slice(0, 300),
        });
      }
    }
    await speechDao.updateSpeechGeneration(pending.id, {
      status: 'failed',
      billingStatus: 'failed',
      ...clearedStorage,
      rawResponse:
        err instanceof AppError
          ? { message: err.message, statusCode: err.statusCode }
          : { message: String(err?.message || err) },
    });
    throw err;
  }

  try {
    await projectStorageService.recalculateProjectStorage(projectId);
  } catch (err) {
    logger.warn('speech_storage_recalc_failed', {
      speechGenerationId: pending.id,
      error: String(err?.message || err).slice(0, 300),
    });
  }
  return updated;
}

const listProjectSpeechGenerations = async (workspaceId, projectId) => {
  await getProjectInWorkspace(workspaceId, projectId);
  return speechDao.listSpeechGenerationsByProject(workspaceId, projectId);
};

const getProjectSpeechGeneration = async (workspaceId, projectId, id) => {
  await getProjectInWorkspace(workspaceId, projectId);
  const row = await speechDao.findSpeechGenerationByIdForProject(id, workspaceId, projectId);
  if (!row) {
    throw new AppError(messages.NOT_FOUND, 404);
  }
  return row;
};

const assertSpeechPlayable = async (workspaceId, projectId, id) => {
  const row = await getProjectSpeechGeneration(workspaceId, projectId, id);
  if (!isSpeechPlayable(row)) {
    throw new AppError(messages.SPEECH_GENERATION_NOT_READY, 409);
  }
  return row;
};

const getPresignedDownloadForSpeech = async (
  workspaceId,
  projectId,
  id,
  expiresInSeconds = PRESIGN_DEFAULT_TTL
) => {
  const row = await assertSpeechPlayable(workspaceId, projectId, id);
  const url = await getPresignedGetUrl(row.s3Key, expiresInSeconds);
  return {
    presignedUrl: url,
    expiresInSeconds,
    speechGeneration: enrichSpeechGenerationForClient(row),
  };
};

module.exports = {
  generateProjectSpeech,
  listProjectSpeechGenerations,
  getProjectSpeechGeneration,
  assertSpeechPlayable,
  getPresignedDownloadForSpeech,
  enrichSpeechGenerationForClient,
  getProjectInWorkspace,
};
