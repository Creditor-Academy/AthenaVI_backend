const { successResponse } = require('../../shared/utils/apiResponse');
const asyncHandler = require('../../shared/utils/asyncHandler');
const messages = require('../../shared/utils/messages');
const imageGenService = require('./imageGen.service');

const listModels = asyncHandler(async (req, res) => {
  const models = imageGenService.listModels();
  return successResponse(req, res, { models }, 200, messages.IMAGE_GEN_MODELS_FETCHED);
});

const listFormats = asyncHandler(async (req, res) => {
  const formats = imageGenService.listFormats();
  return successResponse(req, res, { formats }, 200, messages.IMAGE_GEN_FORMATS_FETCHED);
});

const listStyles = asyncHandler(async (req, res) => {
  const styles = imageGenService.listStyles();
  return successResponse(req, res, { styles }, 200, messages.IMAGE_GEN_STYLES_FETCHED);
});

const estimate = asyncHandler(async (req, res) => {
  const data = imageGenService.creditEstimate(req.query);
  return successResponse(req, res, data, 200, messages.IMAGE_GEN_ESTIMATE);
});

const generate = asyncHandler(async (req, res) => {
  const data = await imageGenService.generate({
    userId: req.user.id,
    workspace: req.workspace,
    body: req.body,
  });
  return successResponse(req, res, data, 201, messages.IMAGE_GEN_CREATED);
});

const regenerate = asyncHandler(async (req, res) => {
  const data = await imageGenService.regenerate({
    userId: req.user.id,
    workspace: req.workspace,
    generationId: req.params.generationId,
    body: req.body || {},
  });
  return successResponse(req, res, data, 201, messages.IMAGE_GEN_REGENERATED);
});

const tweak = asyncHandler(async (req, res) => {
  const data = await imageGenService.tweak({
    userId: req.user.id,
    workspace: req.workspace,
    generationId: req.params.generationId,
    instruction: req.body.instruction,
  });
  return successResponse(req, res, data, 201, messages.IMAGE_GEN_TWEAKED);
});

const listGenerations = asyncHandler(async (req, res) => {
  const generations = await imageGenService.listGenerations({
    userId: req.user.id,
    workspace: req.workspace,
    query: req.query,
  });
  return successResponse(
    req,
    res,
    { generations },
    200,
    messages.IMAGE_GEN_LIST_FETCHED
  );
});

const getGeneration = asyncHandler(async (req, res) => {
  const generation = await imageGenService.getGeneration({
    workspace: req.workspace,
    generationId: req.params.generationId,
  });
  return successResponse(req, res, { generation }, 200, messages.IMAGE_GEN_FETCHED);
});

const download = asyncHandler(async (req, res) => {
  await imageGenService.downloadGeneration({
    req,
    res,
    workspace: req.workspace,
    generationId: req.params.generationId,
    format: req.query.format || 'png',
  });
});

module.exports = {
  listModels,
  listFormats,
  listStyles,
  estimate,
  generate,
  regenerate,
  tweak,
  listGenerations,
  getGeneration,
  download,
};
