const Joi = require('joi');

const createWorkspaceSchema = Joi.object({
  body: Joi.object({
    name: Joi.string().min(3).max(100).required(),
  }),
});

const workspaceByIdSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
});

const listWorkspaceLibrarySchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
  query: Joi.object({
    category: Joi.string().valid('video', 'presentation', 'image').optional(),
    folderId: Joi.string().uuid().optional(),
    take: Joi.number().integer().min(1).max(100).optional(),
    skip: Joi.number().integer().min(0).optional(),
    mode: Joi.string().valid('image').optional(),
  }),
});

const renameWorkspaceSchema = Joi.object({
  body: Joi.object({
    name: Joi.string().min(3).max(100).required(),
  }),
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
});

const inviteMemberSchema = Joi.object({
  body: Joi.object({
    email: Joi.string().email().required(),
    role: Joi.string().valid('OWNER', 'ADMIN', 'MEMBER').required(),
  }),
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
  }),
});

const cancelInvitationSchema = Joi.object({
  params: Joi.object({
    workspaceId: Joi.string().uuid().required(),
    invitationId: Joi.string().uuid().required(),
  }),
});

const acceptInvitationSchema = Joi.object({
  body: Joi.object({
    token: Joi.string().required(),
  }),
});

const getInvitationByTokenSchema = Joi.object({
  params: Joi.object({
    token: Joi.string().uuid().required(),
  }),
});

const removeMemberSchema = Joi.object({ params: Joi.object({
  workspaceId: Joi.string().uuid().required(),
  memberId: Joi.string().uuid().required(),
}) });

const changeMemberRoleSchema = Joi.object({ body: Joi.object({
  role: Joi.string().valid('OWNER', 'ADMIN', 'MEMBER').required(),
}), params: Joi.object({
  workspaceId: Joi.string().uuid().required(),
  memberId: Joi.string().uuid().required(),
}) });

module.exports = {
  createWorkspaceSchema,
  workspaceByIdSchema,
  listWorkspaceLibrarySchema,
  renameWorkspaceSchema,
  inviteMemberSchema,
  acceptInvitationSchema,
  getInvitationByTokenSchema,
  removeMemberSchema,
  changeMemberRoleSchema,
  cancelInvitationSchema,
};

