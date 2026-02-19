const jwt = require('jsonwebtoken');

const signAccessToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: '1m',
  });
};

const verifyAccessToken = (token) => jwt.verify(token, process.env.JWT_SECRET);

module.exports = { signAccessToken, verifyAccessToken };
