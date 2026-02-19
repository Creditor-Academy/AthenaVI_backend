module.exports = {
  // Common
  INTERNAL_SERVER_ERROR: 'Something went wrong',
  INVALID_REQUEST: 'Invalid request',
  UNAUTHORIZED: 'Unauthorized',
  SESSION_EXPIRED: 'Session expired',
  NOT_FOUND: 'Not found',

  // Auth
  INVALID_CREDENTIALS: 'Invalid email or password',
  TOKEN_EXPIRED: 'Token expired',
  TOKEN_GENERATED: 'Token generated successfully',
  REFRESH_TOKEN_MISSING:'Refresh Token missing',
  LOGOUT_SUCCESSFULLY: 'Logged out successfully',

  // User
  USER_NOT_FOUND: 'User not found',
  USER_CREATED: 'User created successfully',
  USER_EMAIL_EXISTS: 'Email already registered',
  USERS_FETCHED_SUCCESSFULLY: 'Users fetched successfully',

  // Database
  DUPLICATE_ENTRY: 'Record already exists',

  // OTP
  EMAIL_REQUIRED: 'Email is required',
  OTP_SENT: 'OTP sent to email',
  EMAIL_SEND_FAILED: 'Failed to send email',
  ALL_FIELDS_REQUIRED: 'All fields are required',
  OTP_NOT_FOUND: 'OTP not found',
  OTP_EXPIRED: 'OTP is expired',
  INVALID_OTP: 'OTP not valid',
  BODY_MISSING: 'Request body is missing',
  WAIT_BEFORE_REQUESTING_OTP: 'Please wait before requesting OTP again',
  TOO_MANY_OTP_REQUESTS: 'Too many OTP requests. Try again later',
  OTP_EXPIRED: 'OTP expired or not found',
  OTP_INVALID: 'Invalid OTP', 
};
