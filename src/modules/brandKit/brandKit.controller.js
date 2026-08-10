const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const brandKitService = require('./brandKit.service');

const listBrandKits = asyncHandler(async (req, res) => {
  const data = await brandKitService.listBrandKits(req.params.workspaceId);
  return successResponse(req, res, { brandKits: data }, 200, messages.BRAND_KITS_FETCHED);
});

const getBrandKit = asyncHandler(async (req, res) => {
  const data = await brandKitService.getBrandKit(req.params.workspaceId, req.params.brandKitId);
  return successResponse(req, res, { brandKit: data }, 200, messages.BRAND_KIT_FETCHED);
});

const createBrandKit = asyncHandler(async (req, res) => {
  const data = await brandKitService.createBrandKit({
    workspaceId: req.params.workspaceId,
    userId: req.user.id,
    name: req.body.name,
    data: req.body.data,
    isDefault: req.body.isDefault,
  });
  return successResponse(req, res, { brandKit: data }, 201, messages.BRAND_KIT_CREATED);
});

const updateBrandKit = asyncHandler(async (req, res) => {
  const data = await brandKitService.updateBrandKit({
    workspaceId: req.params.workspaceId,
    brandKitId: req.params.brandKitId,
    name: req.body.name,
    data: req.body.data,
    isDefault: req.body.isDefault,
  });
  return successResponse(req, res, { brandKit: data }, 200, messages.BRAND_KIT_UPDATED);
});

const setDefaultBrandKit = asyncHandler(async (req, res) => {
  const data = await brandKitService.setDefaultBrandKit(
    req.params.workspaceId,
    req.params.brandKitId
  );
  return successResponse(req, res, { brandKit: data }, 200, messages.BRAND_KIT_DEFAULT_SET);
});

const deleteBrandKit = asyncHandler(async (req, res) => {
  const data = await brandKitService.deleteBrandKit(
    req.params.workspaceId,
    req.params.brandKitId
  );
  return successResponse(req, res, data, 200, messages.BRAND_KIT_DELETED);
});

const uploadMedia = asyncHandler(async (req, res) => {
  const data = await brandKitService.uploadMedia({
    workspaceId: req.params.workspaceId,
    brandKitId: req.params.brandKitId,
    file: req.file,
    kind: req.body.kind,
    role: req.body.role,
    name: req.body.name,
  });
  return successResponse(req, res, { media: data }, 201, messages.BRAND_KIT_MEDIA_UPLOADED);
});

const deleteMedia = asyncHandler(async (req, res) => {
  const data = await brandKitService.deleteMedia({
    workspaceId: req.params.workspaceId,
    brandKitId: req.params.brandKitId,
    mediaId: req.params.mediaId,
  });
  return successResponse(req, res, data, 200, messages.BRAND_KIT_MEDIA_DELETED);
});

const streamMedia = asyncHandler(async (req, res) => {
  await brandKitService.streamMedia({
    workspaceId: req.params.workspaceId,
    brandKitId: req.params.brandKitId,
    mediaId: req.params.mediaId,
    req,
    res,
  });
});

module.exports = {
  listBrandKits,
  getBrandKit,
  createBrandKit,
  updateBrandKit,
  setDefaultBrandKit,
  deleteBrandKit,
  uploadMedia,
  deleteMedia,
  streamMedia,
};
