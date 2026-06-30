const settingsDao = require('../settings/settings.dao');
const { sendEmail } = require('../../shared/notification/email.service');
const { buildProductAnnouncementEmail } = require('../../shared/templates/productAnnouncement.template');
const logger = require('../../shared/utils/logger');

const BATCH_SIZE = 10;
const BATCH_DELAY_MS = 500;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function broadcastProductEmail({ subject, html, text, sentByUserId }) {
  const users = await settingsDao.findUsersWithNotificationPreference('productEmails');
  const recipientCount = users.length;
  let sentCount = 0;
  let failedCount = 0;

  const { subject: emailSubject, text: emailText, html: emailHtml } =
    buildProductAnnouncementEmail({
      subject,
      htmlBody: html,
      textBody: text,
    });

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
      } catch (error) {
        failedCount += 1;
        logger.error('Product email broadcast failed for user', {
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

  logger.info('Product email broadcast completed', {
    sentByUserId,
    subject,
    recipientCount,
    sentCount,
    failedCount,
  });

  return { recipientCount, sentCount, failedCount };
}

module.exports = {
  broadcastProductEmail,
};
