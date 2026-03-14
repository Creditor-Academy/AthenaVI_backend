module.exports = {
  // Common
  INTERNAL_SERVER_ERROR: 'Something went wrong',
  INVALID_REQUEST: 'Invalid request',
  UNAUTHORIZED: 'Unauthorized',
  SESSION_EXPIRED: 'Session expired',
  NOT_FOUND: 'Not found',
  INVALID_IMAGE_TYPE: 'Only JPG, PNG and WEBP images are allowed',
  PROFILE_IMAGE_REQUIRED: 'Profile image is required',

  // Auth
  INVALID_CREDENTIALS: 'Invalid email or password',
  TOKEN_EXPIRED: 'Token expired',
  TOKEN_GENERATED: 'Token generated successfully',
  REFRESH_TOKEN_MISSING:'Refresh Token missing',
  LOGOUT_SUCCESSFULLY: 'Logged out successfully',
  PASSWORD_LINK_SEND: 'If the email exists, a password reset link has been sent',
  PASSWORD_RESET: 'Password reset successful. Please login again',

  // User
  USER_NOT_FOUND: 'User not found',
  USER_CREATED: 'User created successfully',
  USER_EMAIL_EXISTS: 'Email already registered',
  USERS_FETCHED_SUCCESSFULLY: 'Users fetched successfully',
  USER_PROFILE_FETCHED_SUCCESSFULLY: 'User profile fetched successfully',
  NO_VALID_FIELDS_PROVIDED: 'No valid fields provided for update',
  PROFILE_IMAGE_UPLOADED_SUCCESSFULLY: 'Profile image uploaded successfully',
  PROFILE_IMAGE_NOT_FOUND: 'Profile image not found',
  PROFILE_IMAGE_DELETED_SUCCESSFULLY: 'Profile image deleted successfully',

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

  // OAuth
  OAUTH_STATE_INVALID: 'Invalid or expired OAuth state',
  GOOGLE_OAUTH_FAILED: 'Google sign-in failed',

  // Workspace
  WORKSPACE_NOT_FOUND: 'Workspace not found',
  WORKSPACE_FORBIDDEN: 'You do not have access to this workspace',
  WORKSPACE_NAME_REQUIRED: 'Workspace name is required',
  WORKSPACE_CANNOT_DELETE_PRIVATE: 'Private workspace cannot be deleted',
  WORKSPACE_CREATED: 'Workspace created successfully',
  WORKSPACE_DELETED: 'Workspace deleted successfully',
  WORKSPACE_LAST_OWNER: 'Cannot remove the last owner. Transfer ownership first.',
  WORKSPACE_OWNER_CANNOT_REMOVE_SELF: 'Transfer ownership before leaving the workspace',
  WORKSPACE_MEMBER_NOT_FOUND: 'Member not found',
  WORKSPACE_ALREADY_MEMBER: 'User is already a member of this workspace',
  WORKSPACE_INVITATION_EXPIRED: 'Invitation has expired or is invalid',
  WORKSPACE_INVITATION_EMAIL_MISMATCH: 'Invitation was sent to a different email address',
  WORKSPACE_INVITATION_ACCEPTED: 'Invitation accepted successfully',
  WORKSPACE_INVITE_SENT: 'Invitation sent successfully',
  WORKSPACE_MEMBER_REMOVED: 'Member removed successfully',
  WORKSPACE_ROLE_UPDATED: 'Role updated successfully',
  WORKSPACE_ONLY_OWNER_CHANGE_ROLES: 'Only the owner can change member roles',
  WORKSPACE_INVITE_ROLE_INVALID: 'Invitation role must be ADMIN or MEMBER',
  WORKSPACE_NOT_FOUND: 'Workspace not found',


  // Credit
  CREDITS_FETCHED: 'Credits fetched successfully',
  CREDIT_HISTORY_FETCHED: 'Credit history fetched successfully',
};
