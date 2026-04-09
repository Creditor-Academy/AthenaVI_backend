const { successResponse } = require('../../shared/utils/apiResponse');
const asyncHandler = require('../../shared/utils/asyncHandler');
const messages = require('../../shared/utils/messages');
const assetService = require('./asset.service');

const uploadAsset = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const file = req.file;
  const workspace = req.workspace;

  const asset = await assetService.uploadAsset({
    userId,
    workspace,
    file,
  });

  return successResponse(
    req,
    res,
    { asset },
    201,
    messages.ASSET_UPLOADED_SUCCESSFULLY
  );
});

const getAssets = asyncHandler(async (req, res) => {
  const workspace = req.workspace;
  const userId = req.user.id;
  const assets = await assetService.getAssets(userId, workspace, req.query);

  return successResponse(
    req,
    res,
    { assets },
    200,
    messages.ASSETS_FETCHED_SUCCESSFULLY
  );
});

const renameAsset = asyncHandler(async (req, res) => {
  const { assetId } = req.params;
  const { name } = req.body;
  const workspace = req.workspace;

  const asset = await assetService.renameAsset({
    assetId,
    workspaceId: workspace.id,
    name,
  });

  return successResponse(
    req,
    res,
    { asset },
    200,
    messages.ASSET_RENAMED_SUCCESSFULLY
  );
});

const deleteAsset = asyncHandler(async (req, res) => {
  const { assetId } = req.params;
  const workspace = req.workspace;

  const asset = await assetService.deleteAsset({
    assetId,
    workspace,
  });

  return successResponse(
    req,
    res,
    { asset },
    200,
    messages.ASSET_DELETED_SUCCESSFULLY
  );
});




module.exports = {
  uploadAsset,
  getAssets,
  renameAsset,
  deleteAsset,
};
