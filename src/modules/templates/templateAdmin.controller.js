const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const templateAdminService = require('./templateAdmin.service');

const listTemplates = asyncHandler(async (req, res) => {
  const { type, contentType, isActive } = req.query || {};
  const templates = await templateAdminService.listTemplates({ type, contentType, isActive });
  return successResponse(req, res, { templates }, 200, messages.TEMPLATES_FETCHED);
});

const getTemplate = asyncHandler(async (req, res) => {
  const template = await templateAdminService.getTemplate(req.params.templateId);
  return successResponse(req, res, { template }, 200, messages.TEMPLATES_FETCHED);
});

const createTemplate = asyncHandler(async (req, res) => {
  const { name, contentType, variant, schema, type, isActive, version } = req.body;
  const template = await templateAdminService.createTemplate({
    name,
    contentType,
    variant,
    schema,
    type,
    isActive,
    version,
    createdBy: req.user.id,
  });
  return successResponse(req, res, { template }, 201, messages.TEMPLATE_CREATED);
});

const updateTemplate = asyncHandler(async (req, res) => {
  const { name, schema, isActive } = req.body;
  const template = await templateAdminService.updateTemplate({
    id: req.params.templateId,
    name,
    schema,
    isActive,
  });
  return successResponse(req, res, { template }, 200, messages.TEMPLATE_UPDATED);
});

module.exports = {
  listTemplates,
  getTemplate,
  createTemplate,
  updateTemplate,
};
