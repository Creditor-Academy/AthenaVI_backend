const { successResponse } = require('../../shared/utils/apiResponse');
const asyncHandler = require('../../shared/utils/asyncHandler');
const messages = require('../../shared/utils/messages');
const fontsService = require('./fonts.service');

const getCatalog = asyncHandler(async (req, res) => {
  const { q, category, subset, featured, limit } = req.query;
  const result = await fontsService.getCatalog({ q, category, subset, featured, limit });
  return successResponse(req, res, result, 200, messages.FONTS_FETCHED);
});

const getCss = asyncHandler(async (req, res) => {
  const result = fontsService.buildCssHref({ families: req.query.families });
  return successResponse(req, res, result, 200, messages.FONT_CSS_BUILT);
});

module.exports = {
  getCatalog,
  getCss,
};
