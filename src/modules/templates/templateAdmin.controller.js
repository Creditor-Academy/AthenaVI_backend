const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const templateAdminService = require('./templateAdmin.service');
const templateMediaService = require('./templateMedia.service');

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
  const { name, schema, isActive, contentType, variant } = req.body;
  const template = await templateAdminService.updateTemplate({
    id: req.params.templateId,
    name,
    schema,
    isActive,
    contentType,
    variant,
  });
  return successResponse(req, res, { template }, 200, messages.TEMPLATE_UPDATED);
});

const listTemplateMedia = asyncHandler(async (req, res) => {
  const media = await templateMediaService.listMedia(req.params.templateId);
  return successResponse(req, res, { media }, 200, messages.TEMPLATE_MEDIA_FETCHED);
});

const uploadTemplateMedia = asyncHandler(async (req, res) => {
  const media = await templateMediaService.uploadMedia({
    templateId: req.params.templateId,
    file: req.file,
    kind: req.body?.kind,
    slotHint: req.body?.slotHint,
    name: req.body?.name,
  });
  return successResponse(req, res, { media }, 201, messages.TEMPLATE_MEDIA_UPLOADED);
});

const deleteTemplateMedia = asyncHandler(async (req, res) => {
  const result = await templateMediaService.deleteMedia({
    templateId: req.params.templateId,
    mediaId: req.params.mediaId,
  });
  return successResponse(req, res, result, 200, messages.TEMPLATE_MEDIA_DELETED);
});

module.exports = {
  listTemplates,
  getTemplate,
  createTemplate,
  updateTemplate,
  listTemplateMedia,
  uploadTemplateMedia,
  deleteTemplateMedia,
};
