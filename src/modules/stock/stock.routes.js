const express = require('express');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const { checkWorkspaceAccess } = require('../../middlewares/workspaceAccess');
const validate = require('../../middlewares/validate.middleware');
const { searchStockSchema, importStockSchema } = require('./stock.validation');
const stockController = require('./stock.controller');

const router = express.Router();

router.get(
  '/search',
  authMiddleware,
  validate(searchStockSchema),
  stockController.searchStock
);

router.post(
  '/workspaces/:workspaceId/import',
  authMiddleware,
  checkWorkspaceAccess,
  validate(importStockSchema),
  stockController.importStockAsset
);

module.exports = router;
