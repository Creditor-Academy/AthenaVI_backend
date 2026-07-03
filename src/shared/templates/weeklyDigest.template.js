const {
  brandName,
  escapeHtml,
  preferencesUrl,
  frontendUrl,
  wrapEmailHtml,
  statsGrid,
  sectionHeading,
  infoPanel,
  primaryButton,
  secondaryLink,
  firstName,
  BRAND,
} = require('./emailLayout');

const buildWeeklyDigestEmail = ({
  userName,
  periodStart,
  periodEnd,
  stats,
}) => {
  const greetingName = userName ? firstName(userName) : 'there';
  const periodLabel = `${periodStart} – ${periodEnd}`;
  const subject = `Your ${brandName()} weekly digest (${periodStart})`;
  const settingsUrl = preferencesUrl();
  const home = frontendUrl();

  const statItems = [
    { label: 'Renders completed', value: stats.rendersCompleted },
    { label: 'Credits used', value: `${stats.creditsUsed} AC` },
    { label: 'Projects updated', value: stats.projectsUpdated },
    { label: 'New teammates', value: stats.teamMembersJoined },
  ];

  const lines = statItems.map(({ label, value }) => `${label}: ${value}`);

  const text = `Hi ${greetingName},

Your weekly digest

Here is your ${brandName()} activity summary for ${periodLabel}:

${lines.map((l) => `- ${l}`).join('\n')}

Open Virtual Studio: ${home}
Manage notification preferences: ${settingsUrl}

— ${brandName()}`;

  const bodyHtml = `
    ${sectionHeading('Your weekly digest', { align: 'left' })}
    <p style="margin:0 0 20px;color:${BRAND.textPrimary};font-size:15px;line-height:1.65;text-align:left;">
      Here&rsquo;s your activity summary for <strong>${escapeHtml(periodLabel)}</strong>.
    </p>
    ${infoPanel({
      title: 'This week at a glance',
      contentHtml: statsGrid(statItems),
    })}
    <p style="margin:16px 0 0;color:${BRAND.textMuted};font-size:14px;text-align:left;">
      Keep creating &mdash; your projects are waiting.
    </p>
    ${primaryButton({ href: home, label: `Open ${brandName()}`, fullWidth: true })}
    ${secondaryLink({ href: settingsUrl, label: 'Manage notification preferences', align: 'left' })}`;

  const html = wrapEmailHtml({
    preheader: `${stats.rendersCompleted} renders completed, ${stats.creditsUsed} AC used this week.`,
    heroGreeting: `Hi ${escapeHtml(greetingName)}!`,
    headerAlign: 'left',
    bodyHtml,
    variant: 'user',
    includePreferencesLink: true,
  });

  return { subject, text, html };
};

module.exports = {
  buildWeeklyDigestEmail,
};
