const express = require('express');
const Joi = require('joi');
const router = express.Router();
const creditController = require('./credit.controller');
const { authMiddleware } = require('../../middlewares/auth.middlware');
const { requireWorkspaceRole } = require('../../middlewares/requireWorkspaceRole');
const validate = require('../../middlewares/validate.middleware');
const { mapCreditWorkspaceId } = require('../../middlewares/mapCreditWorkspaceId');
const creditValidation = require('../validations/credit.validations');

const anyMember = ['OWNER', 'ADMIN', 'MEMBER'];
const ownerOrAdmin = ['OWNER', 'ADMIN'];
const ownerOnly = ['OWNER'];

const wsAny = [mapCreditWorkspaceId, requireWorkspaceRole(anyMember)];
const wsOwnerOrAdmin = [mapCreditWorkspaceId, requireWorkspaceRole(ownerOrAdmin)];
const wsOwner = [mapCreditWorkspaceId, requireWorkspaceRole(ownerOnly)];

const personalHistorySchema = Joi.object({
  params: Joi.object({}).unknown(false),
  query: Joi.object({
    page: Joi.number().integer().min(1).default(1),
    limit: Joi.number().integer().min(1).max(100).default(20),
  }).unknown(false),
  body: Joi.object({}).unknown(false),
});

router.get('/me', authMiddleware, creditController.getPersonalCredits);

router.get(
  '/me/history',
  authMiddleware,
  validate(personalHistorySchema),
  creditController.getPersonalHistory
);

router.get(
  '/me/estimate',
  authMiddleware,
  validate(creditValidation.personalEstimateQuerySchema),
  creditController.getPersonalEstimate
);

router.get(
  '/:id/estimate',
  authMiddleware,
  ...wsAny,
  validate(creditValidation.workspaceEstimateQuerySchema),
  creditController.getWorkspaceEstimate
);

router.post(
  '/:id/allocate',
  authMiddleware,
  ...wsOwner,
  validate(creditValidation.allocateBodySchema),
  creditController.allocateCredits
);

router.post(
  '/:id/deallocate',
  authMiddleware,
  ...wsOwner,
  validate(creditValidation.allocateBodySchema),
  creditController.deallocateCredits
);

router.get(
  '/:id/usage-by-member',
  authMiddleware,
  ...wsOwnerOrAdmin,
  validate(creditValidation.paginationQuerySchema),
  creditController.getUsageByMember
);

router.get('/:id', authMiddleware, ...wsAny, creditController.getCredits);

router.get(
  '/:id/history',
  authMiddleware,
  ...wsOwnerOrAdmin,
  validate(creditValidation.paginationQuerySchema),
  creditController.getWorkspaceCreditHistory
);

router.get(
  '/:id/my-history',
  authMiddleware,
  ...wsAny,
  validate(creditValidation.paginationQuerySchema),
  creditController.getUserCreditHistory
);

module.exports = router;
