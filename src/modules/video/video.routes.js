const express = require('express');
const router = express.Router({ mergeParams: true });
const { requireWorkspaceRole } = require('../../middlewares/requireWorkspaceRole');
const videoController = require('./video.controller');
const videoValidations = require('../validations/video.validations');
const renderController = require('../render/render.controller');
const renderValidations = require('../validations/render.validations');
const validate = require('../../middlewares/validate.middleware');

const anyMember = ['OWNER', 'ADMIN', 'MEMBER'];

router.post(
  '/',
  requireWorkspaceRole(anyMember),
  validate(videoValidations.createVideoSchema),
  videoController.createVideo
);

router.get(
  '/',
  requireWorkspaceRole(anyMember),
  validate(videoValidations.workspaceIdSchema),
  videoController.getVideos
);

router.get(
  '/:videoId',
  requireWorkspaceRole(anyMember),
  validate(videoValidations.videoIdSchema),
  videoController.getVideoById
);

router.patch(
  '/:videoId',
  requireWorkspaceRole(anyMember),
  validate(videoValidations.updateVideoSchema),
  videoController.updateVideo
);

router.delete(
  '/:videoId',
  requireWorkspaceRole(anyMember),
  validate(videoValidations.videoIdSchema),
  videoController.deleteVideo
);

router.post(
  '/:videoId/align-timeline',
  requireWorkspaceRole(anyMember),
  validate(videoValidations.videoIdSchema),
  videoController.alignTimeline
);

router.post(
  '/:videoId/render',
  requireWorkspaceRole(anyMember),
  validate(renderValidations.startRenderSchema),
  renderController.startRender
);

router.post(
  '/:videoId/scenes',
  requireWorkspaceRole(anyMember),
  validate(videoValidations.createSceneSchema),
  videoController.createScene
);

router.get(
  '/:videoId/scenes',
  requireWorkspaceRole(anyMember),
  validate(videoValidations.videoIdSchema),
  videoController.getScenes
);

router.get(
  '/:videoId/scenes/:sceneId',
  requireWorkspaceRole(anyMember),
  validate(videoValidations.sceneIdSchema),
  videoController.getSceneById
);

router.patch(
  '/:videoId/scenes/:sceneId',
  requireWorkspaceRole(anyMember),
  validate(videoValidations.updateSceneSchema),
  videoController.updateScene
);

router.delete(
  '/:videoId/scenes/:sceneId',
  requireWorkspaceRole(anyMember),
  validate(videoValidations.sceneIdSchema),
  videoController.deleteScene
);

module.exports = router;
