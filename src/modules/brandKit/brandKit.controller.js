const asyncHandler = require('../../shared/utils/asyncHandler');
const { successResponse } = require('../../shared/utils/apiResponse');
const messages = require('../../shared/utils/messages');
const brandKitService = require('./brandKit.service');
const brandKitSuggestService = require('./brandKit.suggest.service');
const brandKitLogoVariantsService = require('./brandKit.logoVariants.service');
const brandKitHealthService = require('./brandKit.health.service');
const brandKitGuidelineService = require('./brandKit.guideline.service');
const brandKitGuidelinePdfService = require('./brandKit.guidelinePdf.service');
const brandKitCredit = require('./brandKitCredit.service');
const crypto = require('crypto');

const listBrandKits = asyncHandler(async (req, res) => {
  const data = await brandKitService.listBrandKits(req.params.workspaceId);
  return successResponse(req, res, { brandKits: data }, 200, messages.BRAND_KITS_FETCHED);
});

const getBrandKit = asyncHandler(async (req, res) => {
  const data = await brandKitService.getBrandKit(req.params.workspaceId, req.params.brandKitId);
  return successResponse(req, res, { brandKit: data }, 200, messages.BRAND_KIT_FETCHED);
});

const createBrandKit = asyncHandler(async (req, res) => {
  const data = await brandKitService.createBrandKit({
    workspaceId: req.params.workspaceId,
    userId: req.user.id,
    name: req.body.name,
    data: req.body.data,
    isDefault: req.body.isDefault,
  });
  return successResponse(req, res, { brandKit: data }, 201, messages.BRAND_KIT_CREATED);
});

const updateBrandKit = asyncHandler(async (req, res) => {
  const data = await brandKitService.updateBrandKit({
    workspaceId: req.params.workspaceId,
    brandKitId: req.params.brandKitId,
    name: req.body.name,
    data: req.body.data,
    isDefault: req.body.isDefault,
  });
  return successResponse(req, res, { brandKit: data }, 200, messages.BRAND_KIT_UPDATED);
});

const setDefaultBrandKit = asyncHandler(async (req, res) => {
  const data = await brandKitService.setDefaultBrandKit(
    req.params.workspaceId,
    req.params.brandKitId
  );
  return successResponse(req, res, { brandKit: data }, 200, messages.BRAND_KIT_DEFAULT_SET);
});

const deleteBrandKit = asyncHandler(async (req, res) => {
  const data = await brandKitService.deleteBrandKit(
    req.params.workspaceId,
    req.params.brandKitId
  );
  return successResponse(req, res, data, 200, messages.BRAND_KIT_DELETED);
});

const uploadMedia = asyncHandler(async (req, res) => {
  const data = await brandKitService.uploadMedia({
    workspaceId: req.params.workspaceId,
    brandKitId: req.params.brandKitId,
    file: req.file,
    kind: req.body.kind,
    role: req.body.role,
    name: req.body.name,
  });
  return successResponse(req, res, { media: data }, 201, messages.BRAND_KIT_MEDIA_UPLOADED);
});

const deleteMedia = asyncHandler(async (req, res) => {
  const data = await brandKitService.deleteMedia({
    workspaceId: req.params.workspaceId,
    brandKitId: req.params.brandKitId,
    mediaId: req.params.mediaId,
  });
  return successResponse(req, res, data, 200, messages.BRAND_KIT_MEDIA_DELETED);
});

const streamMedia = asyncHandler(async (req, res) => {
  await brandKitService.streamMedia({
    workspaceId: req.params.workspaceId,
    brandKitId: req.params.brandKitId,
    mediaId: req.params.mediaId,
    req,
    res,
  });
});

const getBrandKitHealth = asyncHandler(async (req, res) => {
  const kit = await brandKitService.getBrandKit(req.params.workspaceId, req.params.brandKitId);
  const health = brandKitHealthService.computeBrandKitHealth(kit);
  return successResponse(req, res, { health }, 200, messages.BRAND_KIT_HEALTH_FETCHED);
});

const suggestColors = asyncHandler(async (req, res) => {
  const data = await brandKitSuggestService.suggestColors({
    workspaceId: req.params.workspaceId,
    userId: req.user.id,
    tone: req.body.tone,
    tagline: req.body.tagline,
    brandKitId: req.body.brandKitId,
    mediaId: req.body.mediaId,
    file: req.file,
  });
  return successResponse(req, res, { suggestion: data }, 200, messages.BRAND_KIT_SUGGEST_COLORS);
});

const suggestFonts = asyncHandler(async (req, res) => {
  const data = await brandKitSuggestService.suggestFonts({
    workspaceId: req.params.workspaceId,
    userId: req.user.id,
    tone: req.body.tone,
    primaryHex: req.body.primaryHex,
    brandKitId: req.body.brandKitId,
  });
  return successResponse(req, res, { suggestion: data }, 200, messages.BRAND_KIT_SUGGEST_FONTS);
});

const suggestVoice = asyncHandler(async (req, res) => {
  const data = await brandKitSuggestService.suggestVoice({
    workspaceId: req.params.workspaceId,
    userId: req.user.id,
    name: req.body.name,
    tagline: req.body.tagline,
    tone: req.body.tone,
    brandKitId: req.body.brandKitId,
  });
  return successResponse(req, res, { suggestion: data }, 200, messages.BRAND_KIT_SUGGEST_VOICE);
});

const suggestImageStyle = asyncHandler(async (req, res) => {
  const data = await brandKitSuggestService.suggestImageStyle({
    workspaceId: req.params.workspaceId,
    userId: req.user.id,
    tone: req.body.tone,
    colors: req.body.colors,
    colorRoles: req.body.colorRoles,
    brandKitId: req.body.brandKitId,
  });
  return successResponse(req, res, { suggestion: data }, 200, messages.BRAND_KIT_SUGGEST_IMAGE_STYLE);
});

const suggestLogoVariants = asyncHandler(async (req, res) => {
  const applyRoles = req.body.applyRoles || [];
  const feature = brandKitCredit.BRAND_KIT_FEATURE.LOGO_VARIANTS;

  if (applyRoles.length > 0) {
    const estimatedAc = brandKitCredit.getFlatAc(feature);
    await brandKitCredit.assertAfford(req.params.workspaceId, req.user.id, estimatedAc);
  }

  const data = await brandKitLogoVariantsService.suggestLogoVariants({
    workspaceId: req.params.workspaceId,
    brandKitId: req.params.brandKitId,
    applyRoles,
  });

  if (data.variants.some((v) => v.applied)) {
    const hash = crypto
      .createHash('sha256')
      .update(JSON.stringify({ brandKitId: req.params.brandKitId, roles: req.body.applyRoles }))
      .digest('hex')
      .slice(0, 16);

    await brandKitCredit.chargeFlat({
      workspaceId: req.params.workspaceId,
      userId: req.user.id,
      feature,
      idempotencyKey: `brandKit:logo_variants:${req.params.workspaceId}:${hash}`,
      metadata: { brandKitId: req.params.brandKitId, action: 'logo_variants' },
    });
  }

  return successResponse(req, res, data, 200, messages.BRAND_KIT_LOGO_VARIANTS);
});

const generateGuideline = asyncHandler(async (req, res) => {
  const data = await brandKitGuidelineService.generateGuideline({
    workspaceId: req.params.workspaceId,
    userId: req.user.id,
    brandKitId: req.params.brandKitId,
    folderId: req.body.folderId,
  });
  return successResponse(req, res, { guideline: data }, 201, messages.BRAND_KIT_GUIDELINE_GENERATED);
});

const getGuideline = asyncHandler(async (req, res) => {
  const data = await brandKitGuidelineService.getGuidelineInfo(
    req.params.workspaceId,
    req.params.brandKitId
  );
  return successResponse(req, res, { guideline: data }, 200, messages.BRAND_KIT_GUIDELINE_FETCHED);
});

const downloadGuidelinePdf = asyncHandler(async (req, res) => {
  const { buffer, filename, contentType } = await brandKitGuidelinePdfService.generateGuidelinePdf({
    workspaceId: req.params.workspaceId,
    brandKitId: req.params.brandKitId,
  });

  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Length', buffer.length);
  res.setHeader(
    'Content-Disposition',
    `attachment; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(filename)}`
  );
  res.setHeader('Cache-Control', 'no-store');
  return res.status(200).send(buffer);
});

module.exports = {
  listBrandKits,
  getBrandKit,
  createBrandKit,
  updateBrandKit,
  setDefaultBrandKit,
  deleteBrandKit,
  uploadMedia,
  deleteMedia,
  streamMedia,
  getBrandKitHealth,
  suggestColors,
  suggestFonts,
  suggestVoice,
  suggestImageStyle,
  suggestLogoVariants,
  generateGuideline,
  getGuideline,
  downloadGuidelinePdf,
};
