const Joi = require('joi');


const createFolderSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).required(),
  }),
});

const getFoldersSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
});

const renameFolderSchema = Joi.object({
  params: Joi.object({
    folderId: Joi.string().uuid().required(),
  }),
  body: Joi.object({
    name: Joi.string().trim().min(1).max(255).required(),
  }),
});

const deleteFolderSchema = Joi.object({
  params: Joi.object({
    folderId: Joi.string().uuid().required(),
  }),
});   


module.exports = {
  getFoldersSchema,
  createFolderSchema,
  renameFolderSchema,
  deleteFolderSchema
};
