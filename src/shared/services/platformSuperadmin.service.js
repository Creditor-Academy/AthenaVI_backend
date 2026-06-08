const prisma = require('../config/prismaClient');

function parseSuperadminEmails() {
  const raw = process.env.PLATFORM_SUPERADMIN_EMAILS || '';
  return raw
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
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

module.exports = {
  parseSuperadminEmails,
  hasPlatformSuperadminAccess,
  resolvePlatformSuperadminByUserId,
};
