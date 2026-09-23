const express = require('express');
const router = express.Router({ mergeParams: true });
const canvasController = require('./canvas.controller');
const canvasValidations = require('../validations/canvas.validations');
const validate = require('../../middlewares/validate.middleware');

router.get('/', validate(canvasValidations.listCanvasesSchema), canvasController.listCanvases);

router.post('/', validate(canvasValidations.createCanvasSchema), canvasController.createCanvas);

router.get('/:canvasId', validate(canvasValidations.canvasByIdSchema), canvasController.getCanvas);

router.patch(
  '/:canvasId',
  validate(canvasValidations.updateCanvasSchema),
  canvasController.updateCanvas
);

router.patch(
  '/:canvasId/data',
  validate(canvasValidations.saveCanvasDataSchema),
  canvasController.saveCanvasData
);

router.patch(
  '/:canvasId/move-folder',
  validate(canvasValidations.moveCanvasFolderSchema),
  canvasController.moveCanvasToFolder
);

router.delete(
  '/:canvasId',
  validate(canvasValidations.deleteCanvasSchema),
  canvasController.deleteCanvas
);

module.exports = router;
