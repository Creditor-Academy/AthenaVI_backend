const jwt = require('jsonwebtoken');
const { redisClient } = require('../shared/config/redis');
const asyncHandler = require('../shared/utils/asyncHandler');
const AppError = require('../shared/utils/AppError');
const messages = require('../shared/utils/messages');

const authMiddleware = asyncHandler(async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new AppError(messages.UNAUTHORIZED, 401);
  }

  const token = authHeader.split(' ')[1];

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    console.log(err);
    throw new AppError(messages.TOKEN_EXPIRED, 401);
  }

  const { sub: userId, sessionId } = payload;

  if (!userId || !sessionId) {
    throw new AppError(messages.UNAUTHORIZED, 401);
  }
  console.log(sessionId);
  
  const session = await redisClient.get(`session:${sessionId}`);

  if (!session) {
    throw new AppError(messages.SESSION_EXPIRED, 401);
  }
  req.user = {
    id: userId,
    sessionId,
  };

  next();
});

module.exports = { authMiddleware };
