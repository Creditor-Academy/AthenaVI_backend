const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const shareService = require('./presentationShare.service');
const rateLimit = require('./presentationShare.rateLimit.service');

const VIEW_CACHE_MAX_AGE_SEC =
  Number(process.env.PPT_SHARE_VIEW_CACHE_MAX_AGE_SEC) >= 0
    ? Number(process.env.PPT_SHARE_VIEW_CACHE_MAX_AGE_SEC)
    : 30;

/* =========================
   Owner (Bearer + workspace member)
========================= */

const enableShare = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const data = await shareService.enableShare({
    workspaceId,
    presentationId,
    userId: req.user.id,
    ip: req.ip,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SHARE_ENABLED);
});

const getShare = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const data = await shareService.getShare({ workspaceId, presentationId });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SHARE_FETCHED);
});

const updateShare = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const { enabled, expiresAt, access } = req.body;
  const data = await shareService.updateShare({
    workspaceId,
    presentationId,
    userId: req.user.id,
    ip: req.ip,
    enabled,
    expiresAt,
    access,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SHARE_UPDATED);
});

const rotateShare = asyncHandler(async (req, res) => {
  const { workspaceId, presentationId } = req.params;
  const data = await shareService.rotateShare({
    workspaceId,
    presentationId,
    userId: req.user.id,
    ip: req.ip,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SHARE_ROTATED);
});

/* =========================
   Public capability token
========================= */

const getPublicPresentation = asyncHandler(async (req, res) => {
  const { token } = req.params;
  await rateLimit.assertViewAllowed({ ip: req.ip, tokenHash: shareService.hashToken(token) });

  const { etag, data } = await shareService.getPublicPresentation(token);

  res.set('ETag', etag);
  res.set('Cache-Control', `private, max-age=${VIEW_CACHE_MAX_AGE_SEC}`);

  if (req.headers['if-none-match'] === etag) {
    return res.status(304).end();
  }

  return successResponse(req, res, data, 200, messages.PRESENTATION_SHARE_VIEW_FETCHED);
});

const getPublicSession = asyncHandler(async (req, res) => {
  const { token } = req.params;
  res.set('Cache-Control', 'no-store');
  await rateLimit.assertPresenceAllowed({ ip: req.ip });

  const data = await shareService.getPublicSession({ token, user: req.user || null });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SHARE_SESSION_FETCHED);
});

const heartbeatPresence = asyncHandler(async (req, res) => {
  const { token } = req.params;
  const { viewerSessionId, slideIndex } = req.body;
  res.set('Cache-Control', 'no-store');
  await rateLimit.assertPresenceAllowed({ ip: req.ip });

  const data = await shareService.heartbeatPresence({
    token,
    user: req.user || null,
    viewerSessionId,
    slideIndex,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SHARE_PRESENCE_FETCHED);
});

const listPresence = asyncHandler(async (req, res) => {
  const { token } = req.params;
  res.set('Cache-Control', 'no-store');
  await rateLimit.assertPresenceAllowed({ ip: req.ip });

  const data = await shareService.listPresence({ token, user: req.user || null });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SHARE_PRESENCE_FETCHED);
});

const leavePresence = asyncHandler(async (req, res) => {
  const { token } = req.params;
  res.set('Cache-Control', 'no-store');
  await rateLimit.assertPresenceAllowed({ ip: req.ip });

  const data = await shareService.leavePresence({
    token,
    user: req.user || null,
    viewerSessionId: req.query.viewerSessionId,
  });
  return successResponse(req, res, data, 200, messages.PRESENTATION_SHARE_PRESENCE_LEFT);
});

module.exports = {
  enableShare,
  getShare,
  updateShare,
  rotateShare,
  getPublicPresentation,
  getPublicSession,
  heartbeatPresence,
  listPresence,
  leavePresence,
};
