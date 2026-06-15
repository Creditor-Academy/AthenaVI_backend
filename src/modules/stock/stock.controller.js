const { successResponse } = require('../../shared/utils/apiResponse');
const asyncHandler = require('../../shared/utils/asyncHandler');
const messages = require('../../shared/utils/messages');
const stockService = require('./stock.service');

const searchStock = asyncHandler(async (req, res) => {
  const { q, type, page, perPage } = req.query;

  const result = await stockService.searchStock({
    q,
    type,
    page,
    perPage,
  });

  return successResponse(
    req,
    res,
    result,
    200,
    messages.STOCK_SEARCH_SUCCESS
  );
});

const importStockAsset = asyncHandler(async (req, res) => {
  const userId = req.user.id;
  const workspace = req.workspace;
  const { provider, externalId, mediaType, name } = req.body;

  const asset = await stockService.importStockAsset({
    userId,
    workspace,
    provider,
    externalId,
    mediaType,
    name,
  });

  return successResponse(
    req,
    res,
    { asset },
    200,
    messages.STOCK_IMPORTED_SUCCESSFULLY
  );
});

module.exports = {
  searchStock,
  importStockAsset,
};
