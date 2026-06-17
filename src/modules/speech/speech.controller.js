const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const speechService = require('./speech.service');
const s3Service = require('../s3/s3.service');

const createSpeech = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const row = await speechService.generateProjectSpeech({
    userId: req.user.id,
    workspaceId,
    projectId,
    ...req.body,
  });
  return successResponse(
    req,
    res,
    { speechGeneration: speechService.enrichSpeechGenerationForClient(row) },
    201,
    messages.SPEECH_GENERATION_SUCCESS
  );
});

const listSpeechGenerations = asyncHandler(async (req, res) => {
  const { workspaceId, projectId } = req.params;
  const rows = await speechService.listProjectSpeechGenerations(workspaceId, projectId);
  return successResponse(
    req,
    res,
    {
      speechGenerations: rows.map((row) => speechService.enrichSpeechGenerationForClient(row)),
    },
    200,
    messages.SPEECH_GENERATIONS_FETCHED
  );
});

const getSpeechGeneration = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, speechId } = req.params;
  const row = await speechService.getProjectSpeechGeneration(workspaceId, projectId, speechId);
  return successResponse(
    req,
    res,
    { speechGeneration: speechService.enrichSpeechGenerationForClient(row) },
    200,
    messages.SPEECH_GENERATION_FETCHED
  );
});

const downloadSpeech = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, speechId } = req.params;
  const expiresIn = req.query.expiresIn;
  const result = await speechService.getPresignedDownloadForSpeech(
    workspaceId,
    projectId,
    speechId,
    expiresIn
  );
  return successResponse(
    req,
    res,
    {
      presignedUrl: result.presignedUrl,
      expiresInSeconds: result.expiresInSeconds,
      speechGeneration: result.speechGeneration,
    },
    200,
    messages.SPEECH_GENERATION_FETCHED
  );
});

const streamSpeech = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, speechId } = req.params;
  const row = await speechService.assertSpeechPlayable(workspaceId, projectId, speechId);
  await s3Service.streamObjectToResponse(req, res, row.s3Key);
});

const headSpeechStream = asyncHandler(async (req, res) => {
  const { workspaceId, projectId, speechId } = req.params;
  const row = await speechService.assertSpeechPlayable(workspaceId, projectId, speechId);
  const meta = await s3Service.headObjectMeta(row.s3Key);
  res.setHeader('Content-Type', meta.contentType || 'audio/mpeg');
  if (meta.contentLength != null) {
    res.setHeader('Content-Length', String(meta.contentLength));
  }
  if (meta.etag) {
    res.setHeader('ETag', meta.etag);
  }
  res.setHeader('Accept-Ranges', meta.acceptRanges);
  res.setHeader('Cache-Control', 'private, no-cache');
  return res.status(200).end();
});

module.exports = {
  createSpeech,
  listSpeechGenerations,
  getSpeechGeneration,
  downloadSpeech,
  streamSpeech,
  headSpeechStream,
};
