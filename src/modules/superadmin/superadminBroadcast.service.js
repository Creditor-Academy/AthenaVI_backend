const settingsDao = require('../settings/settings.dao');
const { sendEmail } = require('../../shared/notification/email.service');
const { buildProductAnnouncementEmail } = require('../../shared/templates/productAnnouncement.template');
const logger = require('../../shared/utils/logger');
const broadcastDao = require('./superadminBroadcast.dao');

const BATCH_SIZE = 10;
const BATCH_DELAY_MS = 500;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function broadcastProductEmail({ subject, html, text, sentByUserId }) {
  const users = await settingsDao.findUsersWithNotificationPreference('productEmails');
  const recipientCount = users.length;

  const broadcast = await broadcastDao.createBroadcast({
    subject,
    htmlBody: html,
    textBody: text || null,
    sentByUserId,
    recipientCount,
    sentCount: 0,
    failedCount: 0,
  });

  const { subject: emailSubject, text: emailText, html: emailHtml } =
    buildProductAnnouncementEmail({
      subject,
      htmlBody: html,
      textBody: text,
    });

  let sentCount = 0;
  let failedCount = 0;
  const recipientRecords = [];

  for (let i = 0; i < users.length; i += BATCH_SIZE) {
    const batch = users.slice(i, i + BATCH_SIZE);

    for (const user of batch) {
      try {
        await sendEmail({
          to: user.email,
          subject: emailSubject,
          text: emailText,
          html: emailHtml,
        });
        sentCount += 1;
        recipientRecords.push({
          broadcastId: broadcast.id,
          userId: user.id,
          email: user.email,
          name: user.name || null,
          status: 'SENT',
          error: null,
          sentAt: new Date(),
        });
      } catch (error) {
        failedCount += 1;
        recipientRecords.push({
          broadcastId: broadcast.id,
          userId: user.id,
          email: user.email,
          name: user.name || null,
          status: 'FAILED',
          error: error.message || 'Send failed',
          sentAt: null,
        });
        logger.error('Product email broadcast failed for user', {
          broadcastId: broadcast.id,
          userId: user.id,
          sentByUserId,
          error: error.message,
        });
      }
    }

    if (i + BATCH_SIZE < users.length) {
      await delay(BATCH_DELAY_MS);
    }
  }

  await broadcastDao.createRecipients(recipientRecords);
  await broadcastDao.updateBroadcastCounts(broadcast.id, { sentCount, failedCount });

  logger.info('Product email broadcast completed', {
    broadcastId: broadcast.id,
    sentByUserId,
    subject,
    recipientCount,
    sentCount,
    failedCount,
  });

  return {
    broadcastId: broadcast.id,
    recipientCount,
    sentCount,
    failedCount,
  };
}

async function listProductEmailBroadcasts({ page, limit }) {
  return broadcastDao.listBroadcasts({ page, limit });
}

async function getProductEmailBroadcast(broadcastId) {
  return broadcastDao.getBroadcastById(broadcastId);
}

async function listProductEmailBroadcastRecipients({ broadcastId, page, limit, status }) {
  return broadcastDao.listBroadcastRecipients({ broadcastId, page, limit, status });
}


const prisma = require('../../shared/config/prismaClient');

async function resendBroadcastProductEmail({ broadcastId, emails, sentByUserId }) {
  const originalBroadcast = await broadcastDao.getBroadcastById(broadcastId);

  let targetUsers = [];
  if (Array.isArray(emails) && emails.length > 0) {
    const uniqueEmails = [...new Set(emails.map((e) => e.trim().toLowerCase()))];
    const foundUsers = await prisma.user.findMany({
      where: { email: { in: uniqueEmails, mode: 'insensitive' } },
      select: { id: true, email: true, name: true },
    });
    const foundEmailsMap = new Map(foundUsers.map((u) => [u.email.toLowerCase(), u]));

    targetUsers = uniqueEmails.map((email) => {
      const user = foundEmailsMap.get(email);
      return {
        id: user ? user.id : sentByUserId,
        email,
        name: user ? user.name : null,
      };
    });
  } else {
    targetUsers = await settingsDao.findUsersWithNotificationPreference('productEmails');
  }

  const recipientCount = targetUsers.length;

  const newBroadcast = await broadcastDao.createBroadcast({
    subject: originalBroadcast.subject,
    htmlBody: originalBroadcast.htmlBody,
    textBody: originalBroadcast.textBody || null,
    sentByUserId,
    recipientCount,
    sentCount: 0,
    failedCount: 0,
  });

  const { subject: emailSubject, text: emailText, html: emailHtml } =
    buildProductAnnouncementEmail({
      subject: originalBroadcast.subject,
      htmlBody: originalBroadcast.htmlBody,
      textBody: originalBroadcast.textBody,
    });

  let sentCount = 0;
  let failedCount = 0;
  const recipientRecords = [];

  for (let i = 0; i < targetUsers.length; i += BATCH_SIZE) {
    const batch = targetUsers.slice(i, i + BATCH_SIZE);

    for (const user of batch) {
      try {
        await sendEmail({
          to: user.email,
          subject: emailSubject,
          text: emailText,
          html: emailHtml,
        });
        sentCount += 1;
        recipientRecords.push({
          broadcastId: newBroadcast.id,
          userId: user.id,
          email: user.email,
          name: user.name || null,
          status: 'SENT',
          error: null,
          sentAt: new Date(),
        });
      } catch (error) {
        failedCount += 1;
        recipientRecords.push({
          broadcastId: newBroadcast.id,
          userId: user.id,
          email: user.email,
          name: user.name || null,
          status: 'FAILED',
          error: error.message || 'Send failed',
          sentAt: null,
        });
        logger.error('Product email broadcast resend failed for recipient', {
          broadcastId: newBroadcast.id,
          email: user.email,
          sentByUserId,
          error: error.message,
        });
      }
    }

    if (i + BATCH_SIZE < targetUsers.length) {
      await delay(BATCH_DELAY_MS);
    }
  }

  await broadcastDao.createRecipients(recipientRecords);
  await broadcastDao.updateBroadcastCounts(newBroadcast.id, { sentCount, failedCount });

  logger.info('Product email broadcast resend completed', {
    broadcastId: newBroadcast.id,
    originalBroadcastId: broadcastId,
    sentByUserId,
    recipientCount,
    sentCount,
    failedCount,
  });

  return {
    broadcastId: newBroadcast.id,
    recipientCount,
    sentCount,
    failedCount,
  };
}

async function createEmailTemplate({ name, subject, htmlBody, textBody, type, createdByUserId }) {
  return broadcastDao.createEmailTemplate({
    name,
    subject: subject || '',
    htmlBody,
    textBody: textBody || null,
    type: type || 'html',
    createdByUserId,
  });
}

async function listEmailTemplates({ page, limit, search, type } = {}) {
  return broadcastDao.listEmailTemplates({ page, limit, search, type });
}

async function getEmailTemplate(templateId) {
  return broadcastDao.getEmailTemplateById(templateId);
}

async function updateEmailTemplate(templateId, data) {
  return broadcastDao.updateEmailTemplate(templateId, data);
}

async function deleteEmailTemplate(templateId) {
  return broadcastDao.deleteEmailTemplate(templateId);
}

module.exports = {
  broadcastProductEmail,
  listProductEmailBroadcasts,
  getProductEmailBroadcast,
  listProductEmailBroadcastRecipients,
  resendBroadcastProductEmail,
  createEmailTemplate,
  listEmailTemplates,
  getEmailTemplate,
  updateEmailTemplate,
  deleteEmailTemplate,
};
