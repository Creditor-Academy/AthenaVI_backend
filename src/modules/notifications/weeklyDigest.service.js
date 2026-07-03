const prisma = require('../../shared/config/prismaClient');
const settingsDao = require('../settings/settings.dao');
const { sendEmail } = require('../../shared/notification/email.service');
const { buildWeeklyDigestEmail } = require('../../shared/templates/weeklyDigest.template');
const logger = require('../../shared/utils/logger');

function getRollingWindow() {
  const periodEnd = new Date();
  const periodStart = new Date(periodEnd);
  periodStart.setUTCDate(periodStart.getUTCDate() - 7);
  return { periodStart, periodEnd };
}

function formatDateLabel(date) {
  return date.toISOString().slice(0, 10);
}

function getIsoWeekStart(date = new Date()) {
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const day = d.getUTCDay();
  const diff = day === 0 ? -6 : 1 - day;
  d.setUTCDate(d.getUTCDate() + diff);
  d.setUTCHours(0, 0, 0, 0);
  return d;
}

async function buildDigestForUser(userId, { periodStart, periodEnd }) {
  const workspaceMemberships = await prisma.workspaceMember.findMany({
    where: { userId },
    select: { workspaceId: true },
  });
  const workspaceIds = workspaceMemberships.map((m) => m.workspaceId);

  const [rendersCompleted, creditsAgg, projectsUpdated, teamMembersJoined] = await Promise.all([
    prisma.projectRender.count({
      where: {
        triggeredBy: userId,
        status: 'completed',
        completedAt: { gte: periodStart, lt: periodEnd },
      },
    }),
    prisma.creditTransaction.aggregate({
      where: {
        userId,
        type: 'usage',
        amount: { lt: 0 },
        createdAt: { gte: periodStart, lt: periodEnd },
      },
      _sum: { amount: true },
    }),
    workspaceIds.length
      ? prisma.project.count({
          where: {
            workspaceId: { in: workspaceIds },
            updatedBy: userId,
            updatedAt: { gte: periodStart, lt: periodEnd },
          },
        })
      : 0,
    workspaceIds.length
      ? prisma.workspaceMember.count({
          where: {
            workspaceId: {
              in: (
                await prisma.workspace.findMany({
                  where: { id: { in: workspaceIds }, type: 'TEAM' },
                  select: { id: true },
                })
              ).map((w) => w.id),
            },
            userId: { not: userId },
            joinedAt: { gte: periodStart, lt: periodEnd },
          },
        })
      : 0,
  ]);

  const creditsUsed = Math.abs(creditsAgg._sum.amount || 0);

  return {
    rendersCompleted,
    creditsUsed,
    projectsUpdated,
    teamMembersJoined,
  };
}

function hasAnyActivity(stats) {
  return (
    stats.rendersCompleted > 0 ||
    stats.creditsUsed > 0 ||
    stats.projectsUpdated > 0 ||
    stats.teamMembersJoined > 0
  );
}

async function sendWeeklyDigests() {
  const users = await settingsDao.findUsersWithNotificationPreference('weeklyDigestEmail');
  const weekStart = getIsoWeekStart();
  const window = getRollingWindow();
  const periodStartLabel = formatDateLabel(window.periodStart);
  const periodEndLabel = formatDateLabel(window.periodEnd);

  let sentCount = 0;
  let skippedCount = 0;
  let failedCount = 0;

  for (const user of users) {
    const lastSent = user.settings?.lastWeeklyDigestSentAt;
    if (lastSent && new Date(lastSent) >= weekStart) {
      skippedCount += 1;
      continue;
    }

    try {
      const stats = await buildDigestForUser(user.id, window);
      if (!hasAnyActivity(stats)) {
        skippedCount += 1;
        continue;
      }

      const { subject, text, html } = buildWeeklyDigestEmail({
        userName: user.name,
        periodStart: periodStartLabel,
        periodEnd: periodEndLabel,
        stats,
      });

      await sendEmail({ to: user.email, subject, text, html });
      await settingsDao.updateLastWeeklyDigestSentAt(user.id);
      sentCount += 1;
    } catch (error) {
      failedCount += 1;
      logger.error('Weekly digest send failed for user', {
        userId: user.id,
        error: error.message,
      });
    }
  }

  return { recipientCount: users.length, sentCount, skippedCount, failedCount };
}

module.exports = {
  sendWeeklyDigests,
  buildDigestForUser,
  getIsoWeekStart,
};
