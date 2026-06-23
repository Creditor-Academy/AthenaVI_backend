const AppError = require('../utils/AppError');
const messages = require('../utils/messages');
const prisma = require('../config/prismaClient');

function parseEmailList(raw) {
  return String(raw || '')
    .split(',')
    .map((e) => e.trim())
    .filter(Boolean);
}

function parseSuperadminEmails() {
  return parseEmailList(process.env.PLATFORM_SUPERADMIN_EMAILS).map((e) => e.toLowerCase());
}

function getPlatformSuperadminNotificationEmails() {
  const fromNotification = parseEmailList(process.env.PLATFORM_SUPERADMIN_NOTIFICATION_EMAIL);
  if (fromNotification.length > 0) {
    return fromNotification;
  }

  const fromAllowlist = parseEmailList(process.env.PLATFORM_SUPERADMIN_EMAILS);
  if (fromAllowlist.length > 0) {
    return fromAllowlist;
  }

  throw new AppError(messages.STORAGE_UPGRADE_NOTIFICATION_NOT_CONFIGURED, 500);
}

function hasPlatformSuperadminAccess(user) {
  if (!user) return false;
  if (user.isPlatformSuperadmin === true) return true;
  const allowlist = parseSuperadminEmails();
  const email = user.email && String(user.email).trim().toLowerCase();
  return Boolean(email && allowlist.includes(email));
}

async function resolvePlatformSuperadminByUserId(userId) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true, isPlatformSuperadmin: true },
  });

  if (!user) {
    return { user: null, canAccess: false };
  }

  return {
    user,
    canAccess: hasPlatformSuperadminAccess(user),
  };
}

async function listPlatformSuperadminUserIds() {
  const allowlist = parseSuperadminEmails();
  const users = await prisma.user.findMany({
    where: {
      OR: [
        { isPlatformSuperadmin: true },
        ...(allowlist.length
          ? [{ email: { in: allowlist, mode: 'insensitive' } }]
          : []),
      ],
    },
    select: { id: true, email: true, isPlatformSuperadmin: true },
  });

  return users
    .filter((user) => hasPlatformSuperadminAccess(user))
    .map((user) => user.id);
}

module.exports = {
  parseSuperadminEmails,
  getPlatformSuperadminNotificationEmails,
  hasPlatformSuperadminAccess,
  resolvePlatformSuperadminByUserId,
  listPlatformSuperadminUserIds,
};
