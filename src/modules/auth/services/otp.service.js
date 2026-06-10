const { redisClient } = require('../../../shared/config/redis');
const AppError = require('../../../shared/utils/AppError');
const messages = require('../../../shared/utils/messages');

const OTP_TTL = 300;
const LOCK_TTL = 30;
const RESEND_LIMIT = 3;
const RESEND_WINDOW = 60;
const MAX_OTP_VERIFY_ATTEMPTS = 5;

const otpKey = (email) => `otp:${email}`;
const lockKey = (email) => `otp:lock:${email}`;
const resendKey = (email) => `otp:resend:${email}`;
const attemptsKey = (email) => `otp:attempts:${email}`;

const VERIFY_OTP_SCRIPT = `
  local saved = redis.call('GET', KEYS[1])
  if not saved then return -1 end
  if saved ~= ARGV[1] then return 0 end
  redis.call('DEL', KEYS[1])
  redis.call('DEL', KEYS[2])
  redis.call('DEL', KEYS[3])
  redis.call('DEL', KEYS[4])
  return 1
`;

const acquireOtpLock = async (email) => {
  const locked = await redisClient.set(lockKey(email), '1', { NX: true, EX: LOCK_TTL });

  if (!locked) {
    throw new AppError(messages.WAIT_BEFORE_REQUESTING_OTP, 429);
  }
};

const releaseOtpLock = async (email) => {
  await redisClient.del(lockKey(email));
};

const checkResendLimit = async (email) => {
  const count = await redisClient.incr(resendKey(email));

  if (count === 1) {
    await redisClient.expire(resendKey(email), RESEND_WINDOW);
  }

  if (count > RESEND_LIMIT) {
    throw new AppError(messages.TOO_MANY_OTP_REQUESTS, 429);
  }
};

const storeOtp = async (email, otp) => {
  await redisClient.del(attemptsKey(email));
  await redisClient.set(otpKey(email), otp, { EX: OTP_TTL });
};

const clearOtpKeys = async (email) => {
  await redisClient.del(otpKey(email));
  await redisClient.del(resendKey(email));
  await redisClient.del(lockKey(email));
  await redisClient.del(attemptsKey(email));
};

const incrementOtpAttempts = async (email) => {
  const count = await redisClient.incr(attemptsKey(email));

  if (count === 1) {
    await redisClient.expire(attemptsKey(email), OTP_TTL);
  }

  if (count >= MAX_OTP_VERIFY_ATTEMPTS) {
    throw new AppError(messages.TOO_MANY_OTP_VERIFY_ATTEMPTS, 429);
  }

  return count;
};

const verifyOtp = async ({ email, otp }) => {
  const attemptCount = await redisClient.get(attemptsKey(email));
  if (attemptCount && Number(attemptCount) >= MAX_OTP_VERIFY_ATTEMPTS) {
    throw new AppError(messages.TOO_MANY_OTP_VERIFY_ATTEMPTS, 429);
  }

  const result = await redisClient.eval(VERIFY_OTP_SCRIPT, {
    keys: [otpKey(email), resendKey(email), lockKey(email), attemptsKey(email)],
    arguments: [String(otp)],
  });

  if (result === -1) {
    throw new AppError(messages.OTP_EXPIRED, 410);
  }

  if (result === 0) {
    await incrementOtpAttempts(email);
    throw new AppError(messages.OTP_INVALID, 400);
  }

  return true;
};

module.exports = {
  acquireOtpLock,
  releaseOtpLock,
  checkResendLimit,
  storeOtp,
  verifyOtp,
  clearOtpKeys,
  incrementOtpAttempts,
};
