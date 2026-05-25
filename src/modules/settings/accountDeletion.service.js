const prisma = require('../../shared/config/prismaClient');
const { deleteFile } = require('../s3/s3.service');
const logger = require('../../shared/utils/logger');

async function deleteS3KeySafe(key) {
  if (!key) return;

  try {
    await deleteFile(key);
  } catch (error) {
    logger.warn('S3 delete failed during account purge', {
      key,
      error: error.message,
    });
  }
}

function extractS3KeyFromUrl(url) {
  if (!url || typeof url !== 'string') return null;
  const marker = '.amazonaws.com/';
  const index = url.indexOf(marker);
  if (index === -1) return null;
  return url.slice(index + marker.length);
}

async function permanentlyDeleteUser(userId) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: {
      ownedWorkspaces: {
        include: {
          assets: true,
          heygenResponses: true,
          projectRenders: true,
          sceneRenderCaches: true,
        },
      },
    },
  });

  if (!user) {
    return false;
  }

  await deleteS3KeySafe(extractS3KeyFromUrl(user.profileImage));

  for (const workspace of user.ownedWorkspaces) {
    for (const asset of workspace.assets) {
      await deleteS3KeySafe(asset.key);
    }
    for (const response of workspace.heygenResponses) {
      await deleteS3KeySafe(response.s3Key);
    }
    for (const render of workspace.projectRenders) {
      await deleteS3KeySafe(render.s3Key);
    }
    for (const cache of workspace.sceneRenderCaches) {
      await deleteS3KeySafe(cache.s3Key);
    }
  }

  await prisma.$transaction([
    prisma.creditTransaction.deleteMany({ where: { userId } }),
    prisma.user.delete({ where: { id: userId } }),
  ]);

  logger.info('Permanently deleted user account', { userId });
  return true;
}

async function purgeExpiredAccounts() {
  const securityDao = require('./security.dao');
  const dueUsers = await securityDao.findUsersDueForPermanentDeletion();
  let deletedCount = 0;

  for (const { id } of dueUsers) {
    const deleted = await permanentlyDeleteUser(id);
    if (deleted) deletedCount += 1;
  }

  return deletedCount;
}

module.exports = {
  permanentlyDeleteUser,
  purgeExpiredAccounts,
};
