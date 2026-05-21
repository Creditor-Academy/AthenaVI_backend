const express = require('express');

const router = express.Router({ mergeParams: true });
const validate = require('../../middlewares/validate.middleware');
const renderController = require('./render.controller');
const renderValidations = require('./render.validation');

router.get('/', validate(renderValidations.projectRenderParamsSchema), renderController.listRenders);
router.post('/', validate(renderValidations.createRenderSchema), renderController.createRender);
router.get('/:renderId', validate(renderValidations.renderByIdSchema), renderController.getRender);
router.get(
  '/:renderId/download',
  validate(renderValidations.renderByIdSchema),
  renderController.getRenderDownloadUrl
);

module.exports = router;
