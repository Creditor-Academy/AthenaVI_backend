const express = require('express');
const router = express.Router({ mergeParams: true });
const projectController = require('./project.controller');
const projectValidations = require('../validations/project.validations');
const validate = require('../../middlewares/validate.middleware');

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
