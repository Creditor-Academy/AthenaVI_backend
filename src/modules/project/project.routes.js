const express = require('express');
const router = express.Router({ mergeParams: true });
const projectController = require('./project.controller');
const videoTemplateController = require('./videoTemplate.controller');
const projectValidations = require('../validations/project.validations');
const videoTemplateValidations = require('../validations/videoTemplate.validations');
const validate = require('../../middlewares/validate.middleware');
const { requireWorkspaceRole } = require('../../middlewares/requireWorkspaceRole');

const ownerOrAdmin = ['OWNER', 'ADMIN'];

router.get('/', validate(projectValidations.listProjectsSchema), projectController.listProjects);

router.post('/', validate(projectValidations.createProjectSchema), projectController.createProject);

router.get('/:projectId', validate(projectValidations.projectByIdSchema), projectController.getProject);

router.patch(
  '/:projectId',
  validate(projectValidations.updateProjectSchema),
  projectController.updateProject
);

router.patch(
  '/:projectId/data',
  validate(projectValidations.saveProjectDataSchema),
  projectController.saveProjectData
);

router.patch(
  '/:projectId/assignee',
  requireWorkspaceRole(ownerOrAdmin),
  validate(projectValidations.setProjectAssigneeSchema),
  projectController.setProjectAssignee
);

router.post(
  '/:projectId/scenes/from-template',
  validate(videoTemplateValidations.appendSceneFromTemplateSchema),
  videoTemplateController.appendSceneFromTemplate
);

router.patch(
  '/:projectId/move-folder',
  validate(projectValidations.moveProjectFolderSchema),
  projectController.moveProjectToFolder
);

router.delete(
  '/:projectId',
  validate(projectValidations.deleteProjectSchema),
  projectController.deleteProject
);

module.exports = router;
