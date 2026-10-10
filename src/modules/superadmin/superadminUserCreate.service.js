const bcrypt = require('bcrypt');
const crypto = require('crypto');
const AppError = require('../../shared/utils/AppError');
const messages = require('../../shared/utils/messages');
const logger = require('../../shared/utils/logger');
const { normalizeEmail } = require('../../shared/utils/normalizeEmail');
const { isPrismaUniqueConstraintError } = require('../../shared/utils/prismaErrors');
const { getSaltRounds } = require('../../shared/utils/bcryptConfig');
const { toJsonNumber } = require('../../shared/utils/byteSize');
const { sendEmail } = require('../../shared/notification/email.service');
const buildAccountCreatedEmail = require('../../shared/templates/accountCreated.template');
const authDao = require('../auth/auth.dao');
const passwordResetService = require('../auth/services/passwordReset.service');
const superadminDao = require('./superadmin.dao');

const MIN_PASSWORD_LENGTH = 8;
/** bcrypt silently truncates beyond 72 bytes, so longer passwords would be misleading. */
const MAX_PASSWORD_BYTES = 72;
const WELCOME_LINK_EXPIRY_HOURS = 72;

function serializeUser(user) {
  return {
    ...user,
    storageLimit: toJsonNumber(user.storageLimit),
    storageUsed: toJsonNumber(user.storageUsed),
  };
}

function validatePassword(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
    throw new AppError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`, 400);
  }
  if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) {
    throw new AppError(messages.USER_CREATE_PASSWORD_TOO_LONG, 400);
  }
}

const defaultDeps = {
  authDao,
  superadminDao,
  generateResetToken: passwordResetService.generateResetToken,
  sendEmail,
  hashPassword: (plain) => bcrypt.hash(plain, getSaltRounds()),
  randomSecret: () => crypto.randomBytes(32).toString('hex'),
  getFrontendUrl: () => String(process.env.FRONTEND_URL || '').replace(/\/+$/, ''),
  logger,
};

/**
 * Platform-admin account creation.
 *
 * - Mirrors self-service register (verified email, Personal workspace, default storage tier).
 * - If no password is supplied, the account is created with a random secret nobody knows and the
 *   user receives a "set your password" link. A password is never emailed or returned.
 * - A failed welcome email never rolls back the account; it is reported via `welcomeEmailSent`.
 */
function createAdminUserService(overrides = {}) {
  const deps = { ...defaultDeps, ...overrides };

  async function createUserByAdmin({
    name,
    email,
    password,
    sendWelcomeEmail = true,
    createdByUserId,
  }) {
    const normalizedEmail = normalizeEmail(email);
    if (!normalizedEmail) {
      throw new AppError(messages.EMAIL_REQUIRED, 400);
    }
    const trimmedName = String(name || '').trim();
    if (!trimmedName) {
      throw new AppError('Name is required', 400);
    }

    const hasPassword = password !== undefined && password !== null && password !== '';
    if (hasPassword) {
      validatePassword(password);
    } else if (!sendWelcomeEmail) {
      // No password and no email would leave an account nobody can sign in to.
      throw new AppError('Provide a password or enable the welcome email', 400);
    }

    const existing = await deps.authDao.findUserByEmail(normalizedEmail);
    if (existing) {
      throw new AppError(messages.USER_EMAIL_EXISTS, 409);
    }

    const hashedPassword = await deps.hashPassword(hasPassword ? password : deps.randomSecret());

    let created;
    try {
      created = await deps.authDao.createUserWithPrivateWorkspace({
        name: trimmedName,
        email: normalizedEmail,
        password: hashedPassword,
        emailVerified: true,
      });
    } catch (err) {
      // Lost a race with another signup/admin create between the lookup and the insert.
      if (isPrismaUniqueConstraintError(err)) {
        throw new AppError(messages.USER_EMAIL_EXISTS, 409);
      }
      throw err;
    }

    let welcomeEmailSent = false;
    if (sendWelcomeEmail) {
      welcomeEmailSent = await sendWelcome(created);
    }

    deps.logger.info('Admin created user account', {
      createdUserId: created.id,
      createdByUserId: createdByUserId || null,
      welcomeEmailSent,
      passwordSetByAdmin: hasPassword,
    });

    const summary = await deps.superadminDao.findUserSummaryById(created.id);
    const user = summary
      ? serializeUser(summary)
      : { id: created.id, email: created.email, name: created.name };

    return { user, welcomeEmailSent };
  }

  async function sendWelcome(user) {
    try {
      const baseUrl = deps.getFrontendUrl();
      if (!baseUrl) {
        deps.logger.warn('Welcome email skipped: FRONTEND_URL is not configured', {
          userId: user.id,
        });
        return false;
      }
      const token = await deps.generateResetToken(user, {
        expiryMinutes: WELCOME_LINK_EXPIRY_HOURS * 60,
      });
      const mail = buildAccountCreatedEmail({
        name: user.name,
        email: user.email,
        setPasswordLink: `${baseUrl}/reset-password/${token}`,
        expiryHours: WELCOME_LINK_EXPIRY_HOURS,
      });
      await deps.sendEmail({ to: user.email, subject: mail.subject, text: mail.text, html: mail.html });
      return true;
    } catch (err) {
      deps.logger.error('Failed to send admin-created account welcome email', {
        userId: user.id,
        error: err.message,
      });
      return false;
    }
  }

  return { createUserByAdmin };
}

module.exports = {
  createAdminUserService,
  createUserByAdmin: (input) => createAdminUserService().createUserByAdmin(input),
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_BYTES,
  WELCOME_LINK_EXPIRY_HOURS,
};
