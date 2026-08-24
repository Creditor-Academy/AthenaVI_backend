const express = require('express');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const validate = require('../../middlewares/validate.middleware');
const { catalogSchema, cssSchema } = require('./fonts.validation');
const fontsController = require('./fonts.controller');

const router = express.Router();

router.get(
  '/catalog',
  authMiddleware,
  validate(catalogSchema),
  fontsController.getCatalog
);

router.get(
  '/css',
  authMiddleware,
  validate(cssSchema),
  fontsController.getCss
);

module.exports = router;
