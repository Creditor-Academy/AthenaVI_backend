const AppError = require('../shared/utils/AppError');
const messages = require('../shared/utils/messages');
const {
  resolvePlatformSuperadminByUserId,
} = require('../shared/services/platformSuperadmin.service');

async function requirePlatformSuperadmin(req, res, next) {
  try {
    if (!req.user?.id) {
      return next(new AppError(messages.UNAUTHORIZED, 401));
    }

    const { user, canAccess } = await resolvePlatformSuperadminByUserId(req.user.id);

    if (!user) {
      return next(new AppError(messages.UNAUTHORIZED, 401));
    }

    if (!canAccess) {
      return next(new AppError(messages.PLATFORM_SUPERADMIN_REQUIRED, 403));
    }

    req.platformSuperadmin = user;
    return next();
  } catch (err) {
    return next(err);
  }
}

module.exports = { requirePlatformSuperadmin };
