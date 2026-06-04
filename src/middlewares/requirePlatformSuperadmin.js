const AppError = require('../shared/utils/AppError');
const messages = require('../shared/utils/messages');
const prisma = require('../shared/config/prismaClient');

function parseSuperadminEmails() {
  const raw = process.env.PLATFORM_SUPERADMIN_EMAILS || '';
  return raw
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
}

async function requirePlatformSuperadmin(req, res, next) {
  try {
    if (!req.user?.id) {
      return next(new AppError(messages.UNAUTHORIZED, 401));
    }

    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { id: true, email: true, isPlatformSuperadmin: true },
    });

    if (!user) {
      return next(new AppError(messages.UNAUTHORIZED, 401));
    }

    const allowlist = parseSuperadminEmails();
    const emailAllowed =
      user.email && allowlist.includes(String(user.email).trim().toLowerCase());

    if (!user.isPlatformSuperadmin && !emailAllowed) {
      return next(new AppError(messages.PLATFORM_SUPERADMIN_REQUIRED, 403));
    }

    req.platformSuperadmin = user;
    return next();
  } catch (err) {
    return next(err);
  }
}

module.exports = { requirePlatformSuperadmin };
