const express = require('express');
const router = express.Router({ mergeParams: true });
const projectController = require('./project.controller');
const projectValidations = require('../validations/project.validations');
const validate = require('../../middlewares/validate.middleware');
const { requireWorkspaceRole } = require('../../middlewares/requireWorkspaceRole');
const { authMiddleware } = require('../../middlewares/auth.middlware');

const anyMember = ['OWNER', 'ADMIN', 'MEMBER'];

router.post(
  '/:workspaceId',
  authMiddleware,
  requireWorkspaceRole(anyMember),
  validate(projectValidations.createProjectSchema),
  projectController.createProject
);

module.exports = router;
