const crypto = require('crypto');
const earlyAccessDao = require('./earlyAccess.dao');
const earlyAccessRateLimit = require('./earlyAccessRateLimit.service');
const EarlyAccessHttpError = require('./earlyAccess.errors');
const AppError = require('../../shared/utils/AppError');
const { sendEmail } = require('../../shared/notification/email.service');
const {
  getPlatformSuperadminNotificationEmails,
} = require('../../shared/services/platformSuperadmin.service');
const {
  buildEarlyAccessSuperadminNotificationEmail,
  buildEarlyAccessConfirmationEmail,
  buildEarlyAccessStatusUpdateEmail,
} = require('../../shared/templates/earlyAccess.template');
const {
  ALL_STATUSES,
  assertValidDbStatus,
  isTerminalStatus,
  toApiStatus,
  toDbStatus,
} = require('./earlyAccess.status');
const { normalizeEmail } = require('../../shared/utils/normalizeEmail');
const { isPrismaUniqueConstraintError } = require('../../shared/utils/prismaErrors');
const messages = require('../../shared/utils/messages');
const logger = require('../../shared/utils/logger');

function generateRequestId() {
  const suffix = crypto.randomBytes(7).toString('base64url').slice(0, 9);
  return `ea_${suffix}`;
}

function serializeEarlyAccessRequest(record) {
  return {
    requestId: record.id,
    name: record.name,
    email: record.email,
    company: record.company,
    role: record.role,
    useCase: record.useCase,
    message: record.message,
    status: toApiStatus(record.status),
    createdAt: record.createdAt,
    reviewedAt: record.reviewedAt,
    reviewerId: record.reviewerId,
  };
}

async function sendApplicantStatusEmail(request) {
  const { subject, text, html } = buildEarlyAccessStatusUpdateEmail({
    name: request.name,
    email: request.email,
    requestId: request.id,
    status: request.status,
  });

  await sendEmail({
    to: request.email,
    subject,
    text,
    html,
  });
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

async function listEarlyAccessRequestsForAdmin(page, limit, status) {
  const normalizedStatus = status ? toDbStatus(status) : undefined;
  if (normalizedStatus && !assertValidDbStatus(normalizedStatus)) {
    throw new AppError(messages.INVALID_REQUEST, 400);
  }

  const result = await earlyAccessDao.listRequests({
    page,
    limit,
    status: normalizedStatus,
  });

  return {
    requests: result.requests.map(serializeEarlyAccessRequest),
    pagination: result.pagination,
  };
}

async function getEarlyAccessRequestForAdmin(requestId) {
  const request = await earlyAccessDao.findById(requestId);
  if (!request) {
    throw new AppError(messages.EARLY_ACCESS_REQUEST_NOT_FOUND, 404);
  }
  return { request: serializeEarlyAccessRequest(request) };
}

async function updateEarlyAccessRequestStatus({ requestId, status, reviewerId }) {
  const dbStatus = toDbStatus(status);
  if (!assertValidDbStatus(dbStatus)) {
    throw new AppError(messages.INVALID_REQUEST, 400);
  }
  if (dbStatus === 'PENDING') {
    throw new AppError(messages.EARLY_ACCESS_CANNOT_REVERT_TO_PENDING, 400);
  }

  const result = await earlyAccessDao.updateStatus({
    requestId,
    status: dbStatus,
    reviewerId,
  });

  if (!result) {
    throw new AppError(messages.EARLY_ACCESS_REQUEST_NOT_FOUND, 404);
  }
  if (result.error === 'terminal') {
    throw new AppError(messages.EARLY_ACCESS_REQUEST_ALREADY_FINALIZED, 400);
  }
  if (result.error === 'unchanged') {
    throw new AppError(messages.EARLY_ACCESS_STATUS_UNCHANGED, 400);
  }

  try {
    await sendApplicantStatusEmail(result.request);
  } catch (error) {
    logger.error('Early access status email failed', {
      requestId,
      status: dbStatus,
      error: error.message,
    });
  }

  return { request: serializeEarlyAccessRequest(result.request) };
}

async function approveEarlyAccessRequest({ requestId, reviewerId }) {
  return updateEarlyAccessRequestStatus({
    requestId,
    status: 'approved',
    reviewerId,
  });
}

async function rejectEarlyAccessRequest({ requestId, reviewerId }) {
  return updateEarlyAccessRequestStatus({
    requestId,
    status: 'rejected',
    reviewerId,
  });
}

async function countPendingEarlyAccessRequests() {
  return earlyAccessDao.countOpen();
}

module.exports = {
  submitEarlyAccessRequest,
  listEarlyAccessRequestsForAdmin,
  getEarlyAccessRequestForAdmin,
  updateEarlyAccessRequestStatus,
  approveEarlyAccessRequest,
  rejectEarlyAccessRequest,
  countPendingEarlyAccessRequests,
  ALL_STATUSES,
  isTerminalStatus,
};
