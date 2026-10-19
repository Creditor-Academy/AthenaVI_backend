const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const graphicsService = require('./graphics.service');

const listAdmin = asyncHandler(async (req, res) => {
  const data = await graphicsService.listAdmin(req.query || {});
  return successResponse(req, res, data, 200, 'Graphics fetched');
});

const getAdmin = asyncHandler(async (req, res) => {
  const data = await graphicsService.getAdmin(req.params.id);
  return successResponse(req, res, { graphic: data }, 200, 'Graphic fetched');
});

const create = asyncHandler(async (req, res) => {
  const data = await graphicsService.createFromUpload({
    file: req.file,
    body: req.body || {},
    userId: req.user.id,
  });
  return successResponse(req, res, { graphic: data }, 201, 'Graphic created');
});

const update = asyncHandler(async (req, res) => {
  const data = await graphicsService.updateMetadata(req.params.id, req.body || {});
  return successResponse(req, res, { graphic: data }, 200, 'Graphic updated');
});

const publish = asyncHandler(async (req, res) => {
  const data = await graphicsService.publish(req.params.id);
  return successResponse(req, res, { graphic: data }, 200, 'Graphic published');
});

const unpublish = asyncHandler(async (req, res) => {
  const data = await graphicsService.unpublish(req.params.id);
  return successResponse(req, res, { graphic: data }, 200, 'Graphic unpublished');
});

const archive = asyncHandler(async (req, res) => {
  const data = await graphicsService.archive(req.params.id);
  return successResponse(req, res, { graphic: data }, 200, 'Graphic archived');
});

const remove = asyncHandler(async (req, res) => {
  const data = await graphicsService.remove(req.params.id);
  return successResponse(req, res, data, 200, 'Graphic deleted');
});

const listPublished = asyncHandler(async (req, res) => {
  const data = await graphicsService.listPublished(req.query || {});
  return successResponse(req, res, data, 200, 'Graphics fetched');
});

const getPublished = asyncHandler(async (req, res) => {
  const data = await graphicsService.getPublished(req.params.id);
  return successResponse(req, res, { graphic: data }, 200, 'Graphic fetched');
});

const searchPublished = asyncHandler(async (req, res) => {
  const items = await graphicsService.searchPublished(req.body || {});
  return successResponse(req, res, { items }, 200, 'Graphics fetched');
});

const getIllustrationsMeta = asyncHandler(async (req, res) => {
  const data = await graphicsService.getIllustrationsMeta();
  return successResponse(req, res, data, 200, 'GetIllustrations meta fetched');
});

const listGetIllustrationsFree = asyncHandler(async (req, res) => {
  const data = await graphicsService.listGetIllustrationsFree(req.query || {});
  return successResponse(req, res, data, 200, 'GetIllustrations free catalog fetched');
});

const importGetIllustrationsIconPack = asyncHandler(async (req, res) => {
  const data = await graphicsService.importGetIllustrationsIconPack({
    packId: req.params.packId,
    userId: req.user.id,
    publishAssets: req.body?.publishAssets !== false,
  });
  return successResponse(req, res, data, 200, 'GetIllustrations icon pack saved');
});

module.exports = {
  listAdmin,
  getAdmin,
  create,
  update,
  publish,
  unpublish,
  archive,
  remove,
  listPublished,
  getPublished,
  searchPublished,
  getIllustrationsMeta,
  listGetIllustrationsFree,
  importGetIllustrationsIconPack,
};
