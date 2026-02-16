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

// create/store refresh token 

const storeRefreshToken = async({hashedRefreshToken,sessionId, userId})=>{
  console.log(`token: ${hashedRefreshToken}, sessionID: ${sessionId}, userID: ${userId}`);
  
  return await prisma.refreshToken.create({
    data:{
      hashedToken: hashedRefreshToken, 
      sessionId,
      userId,
      expiresAt: new Date(Date.now()+ 7 * 24 * 60 * 60 * 1000)
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

module.exports = {findUserByEmail, createUser, deleteOldOtp , createOtp, findOtpByEmail, storeRefreshToken};
