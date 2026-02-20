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

module.exports = {
  createUser,
  createOtp,
  findUserByEmail,
  deleteOldOtp,
  createPasswordResetToken,
  findValidPasswordResetTokenByHash,
  updatePasswordAndInvalidateResetTokens,
  
};
