const prisma = require('../../shared/config/prismaClient');
const { normalizeEmail } = require('../../shared/utils/normalizeEmail');
const { getDefaultStorageTier } = require('../../shared/config/storagePricing');

const createUser = async (data) => {
  return await prisma.user.create({
    data,
    select: {
      id: true,
      name: true,
      email: true,
    },
  });
};

const createUserWithPrivateWorkspace = async ({
  name,
  email,
  password,
  emailVerified = false,
  profileImage = null,
}) => {
  const defaultTier = getDefaultStorageTier();
  return await prisma.$transaction(async (tx) => {
    const user = await tx.user.create({
      data: {
        name,
        email,
        password,
        emailVerified,
        profileImage,
        storageLimit: defaultTier.limitBytes,
      },
      select: {
        id: true,
        name: true,
        email: true,
      },
    });

    const workspace = await tx.workspace.create({
      data: {
        name: 'Personal',
        type: 'PRIVATE',
        ownerId: user.id,
      },
    });

    await tx.workspaceMember.create({
      data: {
        workspaceId: workspace.id,
        userId: user.id,
        role: 'OWNER',
      },
    });

    await tx.storageTransaction.create({
      data: {
        userId: user.id,
        amountBytes: defaultTier.limitBytes,
        type: 'initial',
        tierId: defaultTier.id,
        metadata: {
          source: 'registration',
        },
      },
    });

    return user;
  });
};

const createPasswordResetToken = async ({ userId, tokenHash, expiresAt }) => {
  await prisma.passwordResetToken.create({
    data: {
      userId,
      tokenHash,
      expiresAt,
    },
  });
};

const findUserByEmail = async (email) => {
  const normalized = normalizeEmail(email);
  if (!normalized) {
    return null;
  }

  return await prisma.user.findUnique({
    where: { email: normalized },
  });
};

const findValidPasswordResetTokenByHash = async (tokenHash) => {
  return await prisma.passwordResetToken.findFirst({
    where: {
      tokenHash,
      expiresAt: { gt: new Date() },
    },
    include: { user: true },
  });
};

const updatePasswordAndInvalidateResetTokens = async ({
  userId,
  hashedPassword,
}) => {
  await prisma.$transaction([
    prisma.user.update({
      where: { id: userId },
      data: { password: hashedPassword },
    }),

    prisma.passwordResetToken.deleteMany({
      where: { userId },
    }),
  ]);
};

const findAccountByProvider = async (provider, providerAccountId) => {
  return prisma.account.findUnique({
    where: {
      provider_providerAccountId: {
        provider,
        providerAccountId,
      },
    },
    include: { user: true },
  });
};

const upsertGoogleAccount = async ({
  userId,
  providerAccountId,
  accessToken,
  refreshToken,
  expiresAt,
  idToken,
}) => {
  await prisma.account.upsert({
    where: {
      provider_providerAccountId: {
        provider: 'google',
        providerAccountId,
      },
    },
    create: {
      userId,
      type: 'oauth',
      provider: 'google',
      providerAccountId,
      accessToken: accessToken || null,
      refreshToken: refreshToken || null,
      expiresAt: expiresAt || null,
      idToken: idToken || null,
    },
    update: {
      accessToken: accessToken ?? undefined,
      refreshToken: refreshToken ?? undefined,
      expiresAt: expiresAt ?? undefined,
      idToken: idToken ?? undefined,
    },
  });
};

module.exports = {
  createPasswordResetToken,
  findValidPasswordResetTokenByHash,
  updatePasswordAndInvalidateResetTokens,
  findUserByEmail,
  createUser,
  createUserWithPrivateWorkspace,
  findAccountByProvider,
  upsertGoogleAccount,
};
