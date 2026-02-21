const prisma = require('../../shared/config/prismaClient');

/* =========================
   CREATE
========================= */

// Create User
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

// Create OTP
const createOtp = async (email, otp) => {
  return await prisma.otp.create({
    data: {
      email,
      code: otp,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    },
  });
};

const createPasswordResetToken = async({userId,tokenHash, expiresAt})=>{
  await prisma.passwordResetToken.create({
    data:{
      userId,
      tokenHash,
      expiresAt
    }
  })
}


/* =========================
   READ
========================= */

// Find user by email
const findUserByEmail = async (email) => {
  return await prisma.user.findUnique({
    where: { email },
  });
};

const findValidPasswordResetTokenByHash =async (tokenHash) => {
  return await prisma.passwordResetToken.findFirst({
    where: {
      tokenHash,
      expiresAt: { gt: new Date() }
    },
    include: { user: true }
  });
};

// Find OTP by email
// const findOtpByEmail = async (email) => {
//   return await prisma.otp.findUnique({
//     where: { email },
//   });
// };


/* =========================
   DELETE
========================= */

// Delete old OTPs
const deleteOldOtp = async (email) => {
  return await prisma.otp.deleteMany({
    where: { email },
  });
};




// mix 
const updatePasswordAndInvalidateResetTokens= async({userId ,hashedPassword})=>{ 
 await prisma.$transaction([
    prisma.user.update({
      where: { id: userId  },
      data: { password: hashedPassword },
    }),

    prisma.passwordResetToken.deleteMany({
      where: { userId: userId },
    }),
  ]);
}


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
  createOtp,
  deleteOldOtp,
  createPasswordResetToken,
  findValidPasswordResetTokenByHash,
  updatePasswordAndInvalidateResetTokens,
  findUserByEmail,
  createUser,
  findAccountByProvider,
  upsertGoogleAccount,
};
