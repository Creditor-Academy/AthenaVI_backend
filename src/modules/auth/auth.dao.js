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

const createOtp = async(email,otp)=>{
  await prisma.otp.create({
    data: {
      email,
      code: otp,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    },
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

const findOtpByEmail = async (email)=>{
  const otpRecord = await prisma.otp.findFirst({
    where:{
      email: email
    }
  })
  return otpRecord;
}

//update


// delete
const deleteOldOtp = async(email)=>{
  await prisma.otp.deleteMany({
    where: {email}
  })
}

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
 * @param {{ userId: string, providerAccountId: string, access_token?: string, refresh_token?: string, expires_at?: number, id_token?: string }}
 */
const upsertGoogleAccount = async ({
  userId,
  providerAccountId,
  access_token,
  refresh_token,
  expires_at,
  id_token,
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
      access_token: access_token || null,
      refresh_token: refresh_token || null,
      expires_at: expires_at || null,
      id_token: id_token || null,
    },
    update: {
      access_token: access_token ?? undefined,
      refresh_token: refresh_token ?? undefined,
      expires_at: expires_at ?? undefined,
      id_token: id_token ?? undefined,
    },
  });
};

module.exports = {
  findUserByEmail,
  createUser,
  deleteOldOtp,
  createOtp,
  findOtpByEmail,
  findAccountByProvider,
  upsertGoogleAccount,
};
