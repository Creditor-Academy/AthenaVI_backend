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

module.exports = {
  broadcastProductEmail,
  listProductEmailBroadcasts,
  getProductEmailBroadcast,
  listProductEmailBroadcastRecipients,
};
