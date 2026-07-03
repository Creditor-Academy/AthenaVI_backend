const {
  brandName,
  escapeHtml,
  preferencesUrl,
  wrapEmailHtml,
  statsGrid,
} = require('./emailLayout');

const buildWeeklyDigestEmail = ({
  userName,
  periodStart,
  periodEnd,
  stats,
}) => {
  const greeting = userName ? `Hi ${userName},` : 'Hi,';
  const periodLabel = `${periodStart} – ${periodEnd}`;
  const subject = `Your ${brandName()} weekly digest (${periodStart})`;
  const settingsUrl = preferencesUrl();

  const statItems = [
    { label: 'Renders completed', value: stats.rendersCompleted },
    { label: 'Credits used', value: `${stats.creditsUsed} AC` },
    { label: 'Projects updated', value: stats.projectsUpdated },
    { label: 'New teammates', value: stats.teamMembersJoined },
  ];

  const lines = statItems.map(({ label, value }) => `${label}: ${value}`);

  const text = `${greeting}

Here is your ${brandName()} activity summary for ${periodLabel}:

${lines.map((l) => `- ${l}`).join('\n')}

Manage notification preferences: ${settingsUrl}

— ${brandName()}`;

  const bodyHtml = `
    <p style="margin:0 0 8px;color:#1A202C;font-size:15px;line-height:1.6;">
      ${escapeHtml(greeting)}
    </p>
    <p style="margin:0 0 8px;color:#64748B;font-size:15px;line-height:1.6;">
      Activity for <strong style="color:#1A202C;">${escapeHtml(periodLabel)}</strong>
    </p>
    ${statsGrid(statItems)}`;

  const html = wrapEmailHtml({
    preheader: `${stats.rendersCompleted} renders completed, ${stats.creditsUsed} AC used this week.`,
    title: 'Your weekly digest',
    bodyHtml,
    variant: 'user',
    includePreferencesLink: true,
  });

  return { subject, text, html };
};

module.exports = {
  buildWeeklyDigestEmail,
};
