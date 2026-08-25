const express = require('express');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const validate = require('../../middlewares/validate.middleware');
const graphicsController = require('./graphics.controller');
const graphicsValidation = require('./graphics.validations');

const router = express.Router();

router.use(authMiddleware);

router.get(
  '/',
  validate(graphicsValidation.listGraphicsQuerySchema),
  graphicsController.listPublished
);

router.post(
  '/search',
  validate(graphicsValidation.searchIntentSchema),
  graphicsController.searchPublished
);

router.get(
  '/:id',
  validate(graphicsValidation.idParams),
  graphicsController.getPublished
);

module.exports = router;
