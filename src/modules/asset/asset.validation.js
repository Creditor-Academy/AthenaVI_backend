const Joi = require('joi');

const uploadAssetSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
});

const getAssetsSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
  query: Joi.object({
    take: Joi.number().integer().min(1).max(100).optional(),
    skip: Joi.number().integer().min(0).optional(),
    source: Joi.string().valid('upload', 'stock', 'all').optional(),
  }),
});

const renameAssetSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
    assetId: Joi.string().uuid().required(),
  }),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).required(),
  }),
});

const deleteAssetSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
    assetId: Joi.string().uuid().required(),
  }),
});

module.exports = {
  uploadAssetSchema,
  getAssetsSchema,
  renameAssetSchema,
  deleteAssetSchema,
};
