const {redisClient} = require('../../shared/config/redis');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');

const OTP_TTL = 300;        // 5 minutes
const LOCK_TTL = 30;       // 30 seconds
const RESEND_LIMIT = 3;    // max attempts
const RESEND_WINDOW = 60;  // per 1 minute

const otpKey = (email) => `otp:${email}`;
const lockKey = (email) => `otp:lock:${email}`;
const resendKey = (email) => `otp:resend:${email}`;

// 1. Prevent rapid OTP requests
const acquireOtpLock = async (email) => {
  const locked = await redisClient.set(
    lockKey(email),
    "1",
    { NX: true, EX: LOCK_TTL }
  );

  if (!locked) {
    throw new AppError(messages.WAIT_BEFORE_REQUESTING_OTP,429);
  }
};

// 2. Limit resend attempts
const checkResendLimit = async (email) => {
  const count = await redisClient.incr(resendKey(email));

  if (count === 1) {
    await redisClient.expire(resendKey(email), RESEND_WINDOW);
  }

  if (count > RESEND_LIMIT) {
    throw new Error(messages.TOO_MANY_OTP_REQUESTS,429);
  }
};

// 3. Store OTP
const storeOtp = async (email, otp) => {
  await redisClient.set(
    otpKey(email),
    otp,
    { EX: OTP_TTL }
  );
};

// 4. Verify OTP
const verifyOtp = async({email,otp})=>{
  const savedOtp = await redisClient.get(otpKey(email))
  console.log(savedOtp);
  

  if (!savedOtp) {
    throw new AppError(messages.OTP_EXPIRED,410);
  }

   if (savedOtp !== String(otp)) {
    throw new AppError(messages.OTP_INVALID,400);
  }
  // cleanup
  await redisClient.del(otpKey(email));
  await redisClient.del(resendKey(email));
  await redisClient.del(lockKey(email));

  return true;
}


module.exports= {
    acquireOtpLock,
    checkResendLimit,
    storeOtp,
    verifyOtp
}

