const crypto = require('crypto');
const earlyAccessDao = require('./earlyAccess.dao');
const earlyAccessRateLimit = require('./earlyAccessRateLimit.service');
const EarlyAccessHttpError = require('./earlyAccess.errors');
const { sendEmail } = require('../../shared/notification/email.service');
const {
  getPlatformSuperadminNotificationEmails,
} = require('../../shared/services/platformSuperadmin.service');
const {
  buildEarlyAccessSuperadminNotificationEmail,
  buildEarlyAccessConfirmationEmail,
} = require('../../shared/templates/earlyAccess.template');
const { normalizeEmail } = require('../../shared/utils/normalizeEmail');
const { isPrismaUniqueConstraintError } = require('../../shared/utils/prismaErrors');
const messages = require('../../shared/utils/messages');

function generateRequestId() {
  const suffix = crypto.randomBytes(7).toString('base64url').slice(0, 9);
  return `ea_${suffix}`;
}

async function submitEarlyAccessRequest(payload, ip) {
  await earlyAccessRateLimit.assertAllowed(ip);

  const normalizedEmail = normalizeEmail(payload.email);
  const existing = await earlyAccessDao.findByEmail(normalizedEmail);

  if (existing) {
    throw new EarlyAccessHttpError({
      statusCode: 409,
      error: 'DUPLICATE_REQUEST',
      message: messages.EARLY_ACCESS_DUPLICATE,
    });
  }

  const requestId = generateRequestId();

  let requestRecord;
  try {
    requestRecord = await earlyAccessDao.create({
      id: requestId,
      name: payload.name.trim(),
      email: normalizedEmail,
      company: payload.company,
      role: payload.role,
      useCase: payload.useCase,
      message: payload.message,
      status: 'PENDING',
    });
  } catch (err) {
    if (isPrismaUniqueConstraintError(err)) {
      throw new EarlyAccessHttpError({
        statusCode: 409,
        error: 'DUPLICATE_REQUEST',
        message: messages.EARLY_ACCESS_DUPLICATE,
      });
    }
    throw err;
  }

  const submittedAt = requestRecord.createdAt.toISOString();
  const notificationEmails = getPlatformSuperadminNotificationEmails();

  const superadminEmail = buildEarlyAccessSuperadminNotificationEmail({
    name: requestRecord.name,
    email: requestRecord.email,
    company: requestRecord.company,
    role: requestRecord.role,
    useCase: requestRecord.useCase,
    message: requestRecord.message,
    requestId,
    submittedAt,
  });

  const confirmationEmail = buildEarlyAccessConfirmationEmail({
    name: requestRecord.name,
    email: requestRecord.email,
    company: requestRecord.company,
    role: requestRecord.role,
    useCase: requestRecord.useCase,
  });

  try {
    await Promise.all([
      sendEmail({
        to: notificationEmails.join(', '),
        subject: superadminEmail.subject,
        text: superadminEmail.text,
        html: superadminEmail.html,
      }),
      sendEmail({
        to: requestRecord.email,
        subject: confirmationEmail.subject,
        text: confirmationEmail.text,
        html: confirmationEmail.html,
      }),
    ]);
  } catch (err) {
    console.error('Early access email send failed:', err);
    throw new EarlyAccessHttpError({
      statusCode: 500,
      error: 'INTERNAL_ERROR',
      message: messages.EARLY_ACCESS_INTERNAL_ERROR,
    });
  }

  const inboxService = require('../inbox/inbox.service');
  inboxService
    .notifyPlatformEarlyAccessRequest({
      requestId,
      name: requestRecord.name,
      email: requestRecord.email,
      company: requestRecord.company,
      role: requestRecord.role,
      useCase: requestRecord.useCase,
    })
    .catch((error) => console.error('Early access platform notification failed:', error));

  await earlyAccessRateLimit.recordSuccess(ip);

  return { requestId };
}

module.exports = {
  submitEarlyAccessRequest,
};
