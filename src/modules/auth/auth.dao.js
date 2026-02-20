const prisma = require('../../shared/config/prismaClient');

// create
const createUser = async(data)=>{
    return await prisma.user.create({data,
        select:{
            name: true,
            email: true,
            id: true
        }
    })
}

// read
const findUserByEmail = async (email) => {
  const user = await prisma.user.findFirst({
    where: {
      email: email,
    },
  });
  return user;
};

//update


// OAuth / Account
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

/**
 * Create or update Google Account and return the user.
 * @param {{ userId: string, providerAccountId: string, accessToken?: string, refreshToken?: string, expiresAt?: number, idToken?: string }}
 */
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
  findUserByEmail,
  createUser,
  findAccountByProvider,
  upsertGoogleAccount,
};
